#!/bin/sh

if [ "$1" = "intake" ]; 
then
	/AdKS/bin/intake-linux64
	exit 0
fi

if [ "$1" = "deliver" ];
then 
	/AdKS/bin/deliver-linux64
	exit 0
fi

if [ "$1" = "validate" ];
then 
	/AdKS/bin/validate-linux64
	exit $?
fi

if [ "$1" = "validate-targets" ];
then 
	/AdKS/bin/validate-targets-linux64
	exit $?
fi
