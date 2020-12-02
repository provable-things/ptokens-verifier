#!/bin/bash

#
# Provable Things Ltd (info@provable.xyz)
#

INFO=1

function logd() {
	local output
	output=""
	if [[ -z "$1" ]]; then read output; else output="$1"; fi
	if ! [[ -z $DEBUG ]]; then >&2 echo "[DEBUG]: $1"; fi
}

function logi() {
	local output
	output=""
	if [[ -z "$1" ]]; then read output; else output="$1"; fi
	if [[ ! -z $DEBUG || ! -z $INFO ]]; then >&2 echo "[INFO]: $output"; fi
}

function loge() {
	echo "[ERROR]: $1"
}

function exit_if_empty() {
	local var
	local err
	local opt

    var=$1
    err=$2
    opt=$3

    if [[ -z "$var" ]]; then
        if [[ "$opt" == "w" ]]; then
            loge "$err"
        else
            loge "$err"
            exit 1
        fi
    fi
}

function apksigner_verify() {
	local path
	path=$1
	__result=$2

	res=`apksigner verify --print-certs $path \
	| sed -n 2,1p \
	| egrep -o '[a-z0-9]{64}'`

	if [[ $? -eq 1 || -z "$res" ]]; then
		loge "APK signer verification failed"
		exit 1
	fi
	
	eval $__result="'$res'"
}


function sha256_apk() {
	local apk_path
	apk_path=$1
	__result=$2

	res=`sha256sum $apk_path | awk '{print $1}'`

	if [[ ! $? -eq 0 || -z "$res" ]]; then
		loge "Failed to get the sha256 of APK"
		exit 1
	fi

	eval $__result="'$res'"
}

function main() {
	local apk_path
	local proof_path
	apk_path=$1
	proof_path=$2

	exit_if_empty "$apk_path" "Invalid path to app"
	exit_if_empty "$proof_path" "Invalid path to the proof"

	local apk_hash
	sha256_apk "$apk_path" apk_hash

	local apk_cert_hash
	apksigner_verify $apk_path apk_cert_hash
	
	logi "APK hash: $apk_hash"
	logi "APK certificate hash: $apk_cert_hash"

	tmp=( "$@" )
    OPTIONS=${tmp[@]:2}

	./src/verify $proof_path $apk_hash $apk_cert_hash $OPTIONS

	if [[ ! $? -eq 0 ]]; then
		loge "Proof not passed"
		exit 1
	fi
	
	logi "Proof passed"

	exit 0
}

main $@