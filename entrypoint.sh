#!/bin/sh

if [ "$1" = "intake" ]; 
then
	eval "echo \"$(cat /AdKS/k8s/config)\"" > /AdKS/k8s/config
	/AdKS/bin/intake-linux64
	exit 0
fi

if [ "$1" = "deliver" ];
then 
	eval "echo \"$(cat /AdKS/k8s/config)\"" > /AdKS/k8s/config
	/AdKS/bin/deliver-linux64
	exit 0
fi

if [ "$1" = "validate" ];
then 
	eval "echo \"$(cat /AdKS/k8s/config)\"" > /AdKS/k8s/config
	/AdKS/bin/validate-linux64
	exit $?
fi

if [ "$1" = "validate-targets" ];
then 
	eval "echo \"$(cat /AdKS/k8s/config)\"" > /AdKS/k8s/config
	/AdKS/bin/validate-targets-linux64
	exit $?
fi
