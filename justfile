set dotenv-load

rootdir := `git rev-parse --show-toplevel`
distdir := rootdir + '/dist'
covdir  := rootdir + '/coverage'

default:
  @just --list

build:
  @mkdir -p "{{distdir}}"
  @go build -o "{{distdir}}/paseto" "{{rootdir}}/cmd/paseto"

[positional-arguments]
test *args:
  #!/usr/bin/env bash
  set -eEuo pipefail

  cov=0
  pkgs=()
  argsa=(-v -race -count=1 -failfast)
  argsb=()

  # It would be nice if Just supported recipe flags, so we could avoid manually
  # parsing arguments. See https://github.com/casey/just/issues/476
  while [ "$#" -gt 0 ]; do
    case $1 in
      -c|--coverage)  cov=1 ;;
      # Other options are passed through to go test
      -*)             argsa+=("$1") ;;
      *)              pkgs+=("$1") ;;
    esac
    shift
  done

  if [ "$cov" -gt 0 ]; then
    mkdir -p "{{covdir}}"
    argsa+=(-coverpkg=./...)
    argsb+=(-args -test.gocoverdir="{{covdir}}")

    echo "Applying Go coverage workaround ..."
    ./bin/fix-missing-go-coverage.sh
  fi

  [ "${#pkgs[@]}" -eq 0 ] && pkgs=(./...)

  go test "${argsa[@]}" "${pkgs[@]}" "${argsb[@]}"

  if [ "$cov" -gt 0 ]; then
    go tool covdata textfmt -i="{{covdir}}" -o "{{covdir}}/coverage.txt"
    fcov report "{{covdir}}/coverage.txt"
  fi


clean:
  @rm -rf "{{distdir}}" "{{covdir}}"
  @git ls-files --others --exclude-standard | grep '_test\.go' | xargs -r rm
