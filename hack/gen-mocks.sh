#!/bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

mockery -dir internal/processor -name CertificateAuthority -output internal/mocks
mockery -dir internal/processor -name KubeAdapter -output internal/mocks
