#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd "$(dirname "$0")/.."
lib_dir=$(pwd)
ca_dir=$(cd ../fabric-ca && pwd)
fabric_dir=$(cd ../fabric && pwd)

vectors="bccsp/composite/testdata/composite-sigs-19/testvectors.json"
results_dir="test-results/composite"
mkdir -p "$results_dir"

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
lib_commit=$(git rev-parse --short HEAD)
lib_tree=$(git status --porcelain -- bccsp scripts | grep -q . && echo dirty || echo clean)
ca_commit=$(git -C "$ca_dir" rev-parse --short HEAD)
ca_tree=$(git -C "$ca_dir" status --porcelain -- util lib vendor/github.com/hyperledger/fabric-lib-go | grep -q . && echo dirty || echo clean)
fabric_commit=$(git -C "$fabric_dir" rev-parse --short HEAD)
fabric_tree=$(git -C "$fabric_dir" status --porcelain -- msp vendor/github.com/hyperledger/fabric-lib-go | grep -q . && echo dirty || echo clean)
record="$lib_dir/$results_dir/${timestamp}_${lib_commit}_${ca_commit}.jsonl"

status=0
(cd "$lib_dir" && go test -count=1 -json -run '^TestComposite' ./bccsp/composite/ ./bccsp/sw/) > "$record" || status=$?
(cd "$ca_dir" && go test -count=1 -json -run '^TestComposite' ./util/ ./lib/) >> "$record" || status=$?
(cd "$fabric_dir" && go test -count=1 -json -run '^TestComposite' ./msp/) >> "$record" || status=$?

passed=$(grep -cE '"Action":"pass","Package":"[^"]*","Test":' "$record" || true)
failed=$(grep -cE '"Action":"fail","Package":"[^"]*","Test":' "$record" || true)
result=$([ "$status" -eq 0 ] && echo PASS || echo FAIL)
vectors_sha=$(sha256sum "$vectors" | cut -d' ' -f1)
go_version=$(go env GOVERSION)

printf '%s\tresult=%s\tmodule=fabric-lib-go+fabric-ca+fabric\tcommit=%s\ttree=%s\tca_commit=%s\tca_tree=%s\tfabric_commit=%s\tfabric_tree=%s\tpassed=%s\tfailed=%s\tgo=%s\tvectors_sha256=%s\trecord=%s\n' \
    "$timestamp" "$result" "$lib_commit" "$lib_tree" "$ca_commit" "$ca_tree" "$fabric_commit" "$fabric_tree" "$passed" "$failed" "$go_version" "$vectors_sha" "$(basename "$record")" \
    | tee -a "$results_dir/history.tsv"

if [ "$status" -ne 0 ]; then
    grep '"Action":"fail"' "$record" | sed -E 's/.*"Package":"([^"]*)".*"Test":"([^"]*)".*/FAIL: \1 \2/' | sort -u
fi

exit "$status"
