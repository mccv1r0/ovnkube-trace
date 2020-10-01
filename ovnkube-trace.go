package main

import (
	"bytes"
	"context"
	"encoding/json"
	//"errors"
	"flag"
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	util "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
)

var (
	logLevels = []string{"debug", "info", "warn", "error", "fatal", "panic"}
	logLevel  = "fatal"
)

const (
	ovnNamespace = "openshift-ovn-kubernetes"
)

type AddrInfo struct {
	Family    string `json:"family,omitempty"`
	Local     string `json:"local,omitempty"`
	Prefixlen int    `json:"prefixlen,omitempty"`
}
type IpAddrReq struct {
	IfIndex   int        `json:"ifindex,omitempty"`
	IfName    string     `json:"ifname,omitempty"`
	LinkIndex int        `json:"link_index,omitempty"`
	AInfo     []AddrInfo `json:"addr_info,omitempty"`
}

type PodInfo struct {
	IP                      string
	MAC                     string
	VethName                string
	PodContainerName        string
	OvnKubePodContainerName string
	NodeName                string
	StorPort                string
	StorMAC                 string
}

func getPodMAC(client *corev1client.CoreV1Client, pod *kapi.Pod) (podMAC string) {

	if pod.Spec.HostNetwork {
		node, err := client.Nodes().Get(context.TODO(), pod.Spec.NodeName, metav1.GetOptions{})
		if err != nil {
			panic(err)
		}

		nodeMAC, err := util.ParseNodeManagementPortMACAddress(node)
		if err != nil {
			panic(err)
		}
		if nodeMAC != nil {
			podMAC = nodeMAC.String()
		}
	} else {
		podAnnotation, err := util.UnmarshalPodAnnotation(pod.ObjectMeta.Annotations)
		if err != nil {
			panic(err)
		}
		if podAnnotation != nil {
			podMAC = podAnnotation.MAC.String()
		}
	}

	return podMAC
}

func getPodInfo(coreclient *corev1client.CoreV1Client, cliConfig string, podName string, namespace string, cmd string) (podInfo *PodInfo, err error) {

	var ethName string

	// Get pod with the name supplied by srcPodName
	pod, err := coreclient.Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		logrus.Errorf("Pod %s in namespace %s not found\n", podName, namespace)
		return nil, err
	}

	// shouldn't this be := ??
	podInfo = &PodInfo{
		IP: pod.Status.PodIP,
	}

	// Get the node on which the src pod runs on
	node, err := coreclient.Nodes().Get(context.TODO(), pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		logrus.Errorf("Pod %s in namespace %s node not found\n", podName, namespace)
		return nil, err
	}
	logrus.Debugf("==>Got pod %s which is running on node %s\n", podName, node.Name)

	var tryJSON bool = true
	var linkIndex int

	// The interface name used depends on what network namespasce the pod uses
	if pod.Spec.HostNetwork {
		ethName = "ovn-k8s-mp0"
		linkIndex = 0
	} else {
		ethName = "eth0"

		// Find index used for pod interface
		var cmdPod *exec.Cmd
		if cliConfig == "" {
			cmdPod = exec.Command("oc", "rsh", "--namespace", namespace, pod.Name)
		} else {
			cmdPod = exec.Command("oc", "rsh", "--namespace", namespace, "--kubeconfig", cliConfig, pod.Name)
		}

		podMAC := getPodMAC(coreclient, pod)
		logrus.Debugf("Using interface name of %s with MAC of %s", ethName, podMAC)

		podInfo.PodContainerName = pod.Name
		podInfo.MAC = podMAC

		var ipOutput string
		var outPod bytes.Buffer

		cmdPod.Stdin = strings.NewReader("ip -j addr show " + ethName)
		cmdPod.Stdout = &outPod
		err = cmdPod.Run()
		if err != nil {
			logrus.Debugf("cmdPod.Run() failed with %s - trying ip addr show without -o json", err)
			tryJSON = false
		}

		if tryJSON {
			logrus.Debugf("==>pod %s: ip addr show: %q", pod.Name, outPod.String())

			var data []IpAddrReq
			ipOutput = strings.Replace(outPod.String(), "\n", "", -1)
			logrus.Debugf("==> pod %s NOW: %s ", pod.Name, ipOutput)
			err = json.Unmarshal([]byte(ipOutput), &data)
			if err != nil {
				fmt.Printf("JSON ERR: couldn't get stuff from data %v; json parse error: %v\n", data, err)
				panic(err)
			}
			logrus.Debugf("size of IpAddrReq array: %v\n", len(data))
			logrus.Debugf("IpAddrReq: %v\n", data)

			for _, addr := range data {
				if addr.IfName == ethName {
					linkIndex = addr.LinkIndex
					logrus.Debugf("ifName: %v", addr.IfName)
					break
				}
			}
			logrus.Debugf("linkIndex is %d", linkIndex)
		} else {
			var cmdPod2 *exec.Cmd
			var outPod2 bytes.Buffer

			if cliConfig == "" {
				cmdPod2 = exec.Command("oc", "rsh", "--namespace", namespace, pod.Name)
			} else {
				cmdPod2 = exec.Command("oc", "rsh", "--namespace", namespace, "--kubeconfig", cliConfig, pod.Name)
			}

			awkString := " | awk '{print $2}'"
			logrus.Debugf("AWK string is %s", awkString)
			cmdPod2.Stdin = strings.NewReader("ip -o link show dev " + ethName + awkString)
			cmdPod2.Stdout = &outPod2

			err = cmdPod2.Run()
			if err != nil {
				logrus.Debugf("cmdPod.Run() failed with %s\n", err)
				// Give up, pod image doesn't have iproute installed
				return nil, err
			}
			logrus.Debugf("==>pod Old Way %s: ip addr show: %q", pod.Name, outPod2.String())

			ipOutput := strings.Replace(outPod2.String(), "\n", "", -1)
			logrus.Debugf("==> pod Old Way %s NOW: %s ", pod.Name, ipOutput)
			ipOutput = strings.Replace(ipOutput, "eth0@if", "", -1)
			logrus.Debugf("==> pod Old Way %s NOW: %s ", pod.Name, ipOutput)
			ipOutput = strings.Replace(ipOutput, ":", "", -1)
			logrus.Debugf("==> pod Old Way %s NOW: %s ", pod.Name, ipOutput)

			linkIndex, err = strconv.Atoi(ipOutput)
			if err != nil {
				logrus.Error("Error converting string to int", err)
				return nil, err
			}
			logrus.Debugf("Old Way - linkIndex is %d", linkIndex)
		}
	}

	if !pod.Spec.HostNetwork && linkIndex == 0 {
		logrus.Fatalf("Fatal: Pod Network used and linkIndex is zero\n")
		return nil, err
	}
	if pod.Spec.HostNetwork && linkIndex != 0 {
		logrus.Errorf("Fatal: Host Network used and linkIndex is non-zero\n")
		return nil, err
	}

	// Get pods in the openshift-ovn-kubernetes namespace
	podsOvn, errOvn := coreclient.Pods(ovnNamespace).List(context.TODO(), metav1.ListOptions{})
	if errOvn != nil {
		logrus.Panicf("Cannot find pods in %s namespace", ovnNamespace)
		return nil, errOvn
	}

	var ovnkubePod *kapi.Pod
	// Find ovnkube-node-xxx pod running on the same node as srcPod
	for _, podOvn := range podsOvn.Items {
		if podOvn.Spec.NodeName == node.Name {
			if strings.HasPrefix(podOvn.Name, "ovnkube-node-metrics") == false {
				if strings.HasPrefix(podOvn.Name, "ovnkube-node") {
					logrus.Debugf("==> pod %s is running on node %s", podOvn.Name, node.Name)
					ovnkubePod = &podOvn
					break
				}
			}
		}
	}
	if ovnkubePod == nil {
		panic(err)
	}

	podInfo.OvnKubePodContainerName = ovnkubePod.Name
	podInfo.NodeName = ovnkubePod.Spec.NodeName
	podInfo.StorPort = "stor-" + ovnkubePod.Spec.NodeName

	//
	// ovn-nbctl  -p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt  --db ssl:10.0.0.6:9641,ssl:10.0.0.8:9641,ssl:10.0.0.7:9641 lsp-get-addresses stor-qe-anurag54-hmprt-master-0

	// Find stor MAC
	var outStor bytes.Buffer
	var cmdStor *exec.Cmd
	if cliConfig == "" {
		cmdStor = exec.Command("oc", "rsh", "--namespace", ovnNamespace, ovnkubePod.Name)
	} else {
		cmdStor = exec.Command("oc", "rsh", "--namespace", ovnNamespace, "--kubeconfig", cliConfig, ovnkubePod.Name)
	}
	cmdStor.Stdin = strings.NewReader("ovn-nbctl " + cmd + " lsp-get-addresses " + "stor-" + ovnkubePod.Spec.NodeName)
	cmdStor.Stdout = &outStor

	logrus.Debugf("command is: %s", "ovn-nbctl "+cmd+" lsp-get-addresses "+"stor-"+ovnkubePod.Spec.NodeName)
	err = cmdStor.Run()
	if err != nil {
		fmt.Printf("cmdStor.Run() failed with %s\n", err)
		logrus.Debugf("cmdStor.Run() failed err %s - podInfo %v - ovnkubePod Name %s",
			err, podInfo, ovnkubePod.Name)
		return nil, err
	}
	podInfo.StorMAC = outStor.String()

	// obnkube-node-xxx uses host network.  Find host end of veth matching pod eth0 index
	var cmdHost *exec.Cmd
	if cliConfig == "" {
		cmdHost = exec.Command("oc", "rsh", "--namespace", ovnNamespace, ovnkubePod.Name)
	} else {
		cmdHost = exec.Command("oc", "rsh", "--namespace", ovnNamespace, "--kubeconfig", cliConfig, ovnkubePod.Name)
	}

	tryJSON = true
	var ipOutput string
	var outHost bytes.Buffer
	var hostInterface string

	cmdHost.Stdin = strings.NewReader("ip -j addr show")
	cmdHost.Stdout = &outHost
	err = cmdHost.Run()
	if err != nil {
		logrus.Debugf("cmdPod.Run() failed with %s - trying ip addr show without -o json", err)
		tryJSON = false
	}

	if tryJSON {
		logrus.Debugf("==>ovnkubePod %s: ip addr show: %q", ovnkubePod.Name, outHost.String())

		var data []IpAddrReq
		ipOutput = strings.Replace(outHost.String(), "\n", "", -1)
		logrus.Debugf("==> host %s NOW: %s", ovnkubePod.Name, ipOutput)
		err = json.Unmarshal([]byte(ipOutput), &data)
		if err != nil {
			logrus.Errorf("JSON ERR: couldn't get stuff from data %v; json parse error: %v", data, err)
			return nil, err
		}
		logrus.Debugf("size of IpAddrReq array: %v", len(data))
		logrus.Debugf("IpAddrReq: %v", data)

		for _, addr := range data {
			if addr.IfIndex == linkIndex {
				hostInterface = addr.IfName
				logrus.Debugf("ifName: %v\n", addr.IfName)
				break
			}
		}
		logrus.Debugf("hostInterface is %s", hostInterface)
	} else {

		var cmdHost2 *exec.Cmd
		if cliConfig == "" {
			cmdHost2 = exec.Command("oc", "rsh", "--namespace", ovnNamespace, ovnkubePod.Name)
		} else {
			cmdHost2 = exec.Command("oc", "rsh", "--namespace", ovnNamespace, "--kubeconfig", cliConfig, ovnkubePod.Name)
		}
		cmdHost2.Stdin = strings.NewReader("ip -o addr show")
		var outHost2 bytes.Buffer
		cmdHost2.Stdout = &outHost2
		err = cmdHost2.Run()
		if err != nil {
			logrus.Errorf("cmdHost2.Run() failed with %s", err)
			return nil, err
		}

		hostOutput := strings.Replace(outHost2.String(), "\n", "", -1)
		logrus.Debugf("==>node %s: ip addr show: %q", node.Name, hostOutput)

		idx := strconv.Itoa(linkIndex) + ": "
		result := strings.Split(hostOutput, idx)
		logrus.Debugf("result[0]: %s", result[0])
		logrus.Debugf("result[1]: %s", result[1])
		words := strings.Fields(result[1])
		for i, word := range words {
			if i == 0 {
				hostInterface = word
				break
			}
		}
	}
	logrus.Debugf("hostInterface name is %s\n", hostInterface)
	podInfo.VethName = hostInterface

	return podInfo, err
}

func setupLogging() {
	var found bool
	for _, l := range logLevels {
		if l == strings.ToLower(logLevel) {
			found = true
			break
		}
	}
	if !found {
		fmt.Fprintf(os.Stderr, "Log Level %q is not supported, choose from: %s\n", logLevel, strings.Join(logLevels, ", "))
		os.Exit(1)
	}

	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		os.Exit(1)
	}
	logrus.SetLevel(level)

	if logrus.IsLevelEnabled(logrus.InfoLevel) {
		logrus.Infof("%s filtering at log level %s", os.Args[0], logrus.GetLevel())
	}
}

func main() {
	var pnamespace *string
	var protocol string

	pnamespace = flag.String("namespace", "default", "k8s namespace to list")

	cliConfig := flag.String("kubeconfig", "", "absolute path to the kubeconfig file")

	srcPodName := flag.String("source", "", "source: source pod name")
	dstPodName := flag.String("dest", "", "dest: destination pod name")
	dstSvcName := flag.String("service", "", "service: destination service name")
	dstPort := flag.String("dest-port", "80", "dest-port: destination port")
	tcp := flag.Bool("tcp", false, "use tcp transport protocol")
	udp := flag.Bool("udp", false, "use udp transport protocol")

	loglevel := flag.String("log-level", "error", "log-level")

	flag.Parse()
	namespace := *pnamespace
	logLevel = *loglevel

	setupLogging()

	logrus.Debugf("log level is set to Debug")

	if *srcPodName == "" {
		fmt.Printf("Usage: source pod must be specified\n")
		logrus.Errorf("Usage: source pod must be specified")
		os.Exit(-1)
	}
	if !*tcp && !*udp {
		fmt.Printf("Usage: either tcp or udp must be specified\n")
		logrus.Errorf("Usage: either tcp or udp must be specified")
		os.Exit(-1)
	}
	if *udp && *tcp {
		fmt.Printf("Usage: Both tcp or udp cannot be specified\n")
		logrus.Errorf("Usage: Both tcp or udp cannot be specified")
		os.Exit(-1)
	}
	if *tcp {
		if *dstSvcName == "" && *dstPodName == "" {
			fmt.Printf("Usage: destination pod or destination service must be specified for tcp\n")
			logrus.Errorf("Usage: destination pod or destination service must be specified for tcp")
			os.Exit(-1)
		} else {
			protocol = "tcp"
		}
	}
	if *udp && *dstPodName == "" {
		fmt.Printf("Usage: destination pod must be specified for udp\n")
		logrus.Errorf("Usage: destination pod must be specified for udp")
		os.Exit(-1)
	} else {
		protocol = "udp"
	}

	var restconfig *rest.Config
	var err error

	// This might work better?  https://godoc.org/sigs.k8s.io/controller-runtime/pkg/client/config

	// When supplied the kubeconfig supplied via cli takes precedence
	if *cliConfig != "" {

		// use the current context in kubeconfig
		restconfig, err = clientcmd.BuildConfigFromFlags("", *cliConfig)
		if err != nil {
			logrus.Errorf(" Unexpected error: %v", err)
			os.Exit(-1)
		}
		//kubeconfig := os.Getenv("KUBECONFIG")
		//fmt.Printf("**cli: kubeconfig: type %T value: %s\n", kubeconfig, kubeconfig)
	} else {

		// Instantiate loader for kubeconfig file.
		kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{},
		)

		// Get a rest.Config from the kubeconfig file.  This will be passed into all
		// the client objects we create.
		restconfig, err = kubeconfig.ClientConfig()
		if err != nil {
			logrus.Errorf(" Unexpected error: %v", err)
			os.Exit(-1)
		}
	}

	// Create a Kubernetes core/v1 client.
	coreclient, err := corev1client.NewForConfig(restconfig)
	if err != nil {
		logrus.Errorf(" Unexpected error: %v", err)
		os.Exit(-1)
	}

	// List all Nodes.
	nodes, err := coreclient.Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		logrus.Errorf(" Unexpected error: %v", err)
		os.Exit(-1)
	}

	masters := make(map[string]string)
	workers := make(map[string]string)

	logrus.Debugf(" Nodes: ")
	for _, node := range nodes.Items {

		_, found := node.Labels["node-role.kubernetes.io/master"]
		if found {
			logrus.Debugf("  Name: %s is a master", node.Name)
			for _, s := range node.Status.Addresses {
				logrus.Debugf("  Address Type: %s - Address: %s", s.Type, s.Address)
				//if s.Type == corev1client.NodeInternalIP {
				if s.Type == "InternalIP" {
					masters[node.Name] = s.Address
				}
			}
		} else {
			logrus.Debugf("  Name: %s is a worker", node.Name)
			for _, s := range node.Status.Addresses {
				logrus.Debugf("  Address Type: %s - Address: %s", s.Type, s.Address)
				//if s.Type == corev1client.NodeInternalIP {
				if s.Type == "InternalIP" {
					workers[node.Name] = s.Address
				}
			}
		}
	}

	if len(masters) != 3 {
		logrus.Fatalf("Must have 3 masters, found %d", len(masters))
		os.Exit(-1)
	}

	nbcmd := "-p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt --db "
	nbCount := 0
	for k, v := range masters {
		logrus.Debugf("master name: %s has IP %s", k, v)
		nbcmd = nbcmd + "ssl:" + v + ":9641"
		if nbCount == 2 {
			nbcmd = nbcmd + " "
		} else {
			nbcmd = nbcmd + ","
		}
		nbCount++
	}
	logrus.Debugf("nbcmd is %s", nbcmd)

	sbcmd := "-p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt --db "
	sbCount := 0
	for _, v := range masters {
		sbcmd = sbcmd + "ssl:" + v + ":9642"
		if sbCount == 2 {
			sbcmd = sbcmd + " "
		} else {
			sbcmd = sbcmd + ","
		}
		sbCount++
	}
	logrus.Debugf("sbcmd is %s", sbcmd)

	// Get info needed for the src Pod
	srcPodInfo, err := getPodInfo(coreclient, *cliConfig, *srcPodName, namespace, nbcmd)
	if err != nil {
		fmt.Printf("Failed to get information from pod %s: %v\n", *srcPodName, err)
		logrus.Errorf("Failed to get information from pod %s: %v", *srcPodName, err)
		os.Exit(-1)
	}
	logrus.Debugf("srcPodInfo is %v", srcPodInfo)

	// Now get info needed for the dst Pod
	dstPodInfo, err := getPodInfo(coreclient, *cliConfig, *dstPodName, namespace, nbcmd)
	if err != nil {
		fmt.Printf("Failed to get information from pod %s: %v\n", *dstPodName, err)
		logrus.Errorf("Failed to get information from pod %s: %v", *dstPodName, err)
		os.Exit(-1)
	}
	logrus.Debugf("dstPodInfo is %v\n", dstPodInfo)

	// Trace from src pod to dst pod
	var outSrcTrace bytes.Buffer
	var cmdSrcTrace *exec.Cmd
	if *cliConfig == "" {
		cmdSrcTrace = exec.Command("oc", "rsh", "--namespace", ovnNamespace, srcPodInfo.OvnKubePodContainerName)
	} else {
		cmdSrcTrace = exec.Command("oc", "rsh", "--namespace", ovnNamespace, "--kubeconfig", *cliConfig, srcPodInfo.OvnKubePodContainerName)
	}

	fromSrc := srcPodInfo.NodeName
	fromSrc += " 'inport==\"" + namespace + "_" + *srcPodName + "\""
	fromSrc += " && eth.dst==" + srcPodInfo.StorMAC
	fromSrc += " && eth.src==" + srcPodInfo.MAC
	fromSrc += " && ip4.dst==" + dstPodInfo.IP
	fromSrc += " && ip4.src==" + srcPodInfo.IP
	fromSrc += " && ip.ttl==64"
	fromSrc += " && " + protocol + ".dst==" + *dstPort + " && " + protocol + ".src==52888'"

	logrus.Debugf("trace command is %s", fromSrc)

	cmdSrcTrace.Stdin = strings.NewReader("ovn-trace " + sbcmd + " " + fromSrc)
	cmdSrcTrace.Stdout = &outSrcTrace

	logrus.Debugf("command is: %s", "ovn-trace "+sbcmd+" "+fromSrc)
	err = cmdSrcTrace.Run()
	if err != nil {
		fmt.Printf("cmdSrcTrace.Run() failed with %s\n", err)
		logrus.Fatalf("cmdSrcTrace.Run() failed with %s", err)
		os.Exit(-1)
	}
	logrus.Debugf("Source to Destination ovn-trace Output: %s", outSrcTrace.String())
	fmt.Printf("Source to Destination ovn-trace Output: %s", outSrcTrace.String())

	// Trace from dst pod to src pod
	var outDstTrace bytes.Buffer
	var cmdDstTrace *exec.Cmd
	if *cliConfig == "" {
		cmdDstTrace = exec.Command("oc", "rsh", "--namespace", ovnNamespace, dstPodInfo.OvnKubePodContainerName)
	} else {
		cmdDstTrace = exec.Command("oc", "rsh", "--namespace", ovnNamespace, "--kubeconfig", *cliConfig, dstPodInfo.OvnKubePodContainerName)
	}

	fromDst := dstPodInfo.NodeName
	fromDst += " 'inport==\"" + namespace + "_" + *dstPodName + "\""
	fromDst += " && eth.dst==" + dstPodInfo.StorMAC
	fromDst += " && eth.src==" + dstPodInfo.MAC
	fromDst += " && ip4.dst==" + srcPodInfo.IP
	fromDst += " && ip4.src==" + dstPodInfo.IP
	fromDst += " && ip.ttl==64"
	fromDst += " && " + protocol + ".src==" + *dstPort + " && " + protocol + ".dst==52888'"

	logrus.Debugf("trace command is %s", fromDst)

	cmdDstTrace.Stdin = strings.NewReader("ovn-trace " + sbcmd + " " + fromDst)
	cmdDstTrace.Stdout = &outDstTrace

	logrus.Debugf("command is: %s\n", "ovn-trace "+sbcmd+" "+fromDst)
	err = cmdDstTrace.Run()
	if err != nil {
		fmt.Printf("cmdTrace.Run() failed with %s\n", err)
		logrus.Fatalf("cmdSrcTrace.Run() failed with %s", err)
		os.Exit(-1)
	}
	logrus.Debugf("Destination to Source ovn-trace Output: %s\n", outDstTrace.String())
	fmt.Printf("Destination to Source ovn-trace Output: %s\n", outDstTrace.String())

	// ovs-appctl ofproto/trace: src pod to dst pod

	if *cliConfig == "" {
		cmdSrcTrace = exec.Command("oc", "rsh", "--namespace", ovnNamespace, srcPodInfo.OvnKubePodContainerName)
	} else {
		cmdSrcTrace = exec.Command("oc", "rsh", "--namespace", ovnNamespace, "--kubeconfig", *cliConfig, srcPodInfo.OvnKubePodContainerName)
	}

	fromSrc = "ofproto/trace br-int" 
	fromSrc += " \"in_port=" + srcPodInfo.VethName + ", " + protocol + ","
	fromSrc += " dl_dst=" + srcPodInfo.StorMAC + ","
	fromSrc += " dl_src=" + srcPodInfo.MAC + ","
	fromSrc += " nw_dst=" + dstPodInfo.IP + ","
	fromSrc += " nw_src=" + srcPodInfo.IP + ","
	fromSrc += " nw_ttl=64" + ","
	fromSrc += " " + protocol + "_dst=" + *dstPort + ","
	fromSrc += " " + protocol + "_src=" + "12345 \""

	logrus.Debugf("trace command is %s", fromSrc)

	cmdSrcTrace.Stdin = strings.NewReader("ovs-appctl " + fromSrc)
	cmdSrcTrace.Stdout = &outSrcTrace

	logrus.Debugf("command is: %s", "ovs-appctl " + fromSrc)
	err = cmdSrcTrace.Run()
	if err != nil {
		fmt.Printf("cmdSrcTrace.Run() failed with %s\n", err)
		logrus.Fatalf("cmdSrcTrace.Run() failed with %s", err)
		os.Exit(-1)
	}
	logrus.Debugf("Source to Destination ovs-appctl Output: %s", outSrcTrace.String())
	fmt.Printf("Source to Destination ovs-appctl Output: %s", outSrcTrace.String())

	// TODO Next
	//
}
