# Makefile
# Build shelloverreversessh
# By J. Stuart McMurray
# Created 20220201
# Last Modified 20220201

.PHONY: shelloverreversessh vet test clean getlocalkey

all: shelloverreversessh

shelloverreversessh: bin/shelloverreversessh

bin/shelloverreversessh: cmd/shelloverreversessh/shelloverreversessh.go cmd/shelloverreversessh/key key.pub
	@mkdir -p bin
	go build -ldflags='${GOLDFLAGS}' -trimpath -o $@ cmd/shelloverreversessh/shelloverreversessh.go
	
cmd/shelloverreversessh/key: bin/genkey
	if ! [ -f $@ ]; then \
		bin/genkey -out cmd/shelloverreversessh/key; \
	else \
		touch cmd/shelloverreversessh/key; \
	fi

key.pub:
	if ! [ -h key.pub ]; then ln -s cmd/shelloverreversessh/key.pub; fi

bin/genkey: cmd/genkey/genkey.go
	@mkdir -p bin
	go build -trimpath -o $@ cmd/genkey/genkey.go

clean:
	if [ -f bin/shelloverreversessh ]; then \
		rm bin/shelloverreversessh; \
	fi

distclean:
	if [ -d bin ]; then rm -rf bin; fi
	if [ -h key.pub ]; then rm key.pub; fi
	for f in \
		cmd/shelloverreversessh/key \
		cmd/shelloverreversessh/key.pub; do \
		if [ -f $$f ]; then \
			rm $$f; \
		fi \
	done

getlocalkey:
	ssh-keyscan 127.0.0.1 | ssh-keygen -lf -

vet:
	go vet ./...
