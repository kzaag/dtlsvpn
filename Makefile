
OPTS=-Wall -Wpedantic -pedantic -Wextra
FILES=main.c

build:
	@gcc -lssl -lcrypto -lpthread $(FILES) $(OPTS) -D SERVER -o bin/vpn

ca:
	openssl ecparam -name prime256v1 -genkey -noout -out ca.key
	openssl req -x509 -key ca.key -out ca.cert -sha384 -days 180 -sha384 -nodes -subj "/CN=ca.com"

NAME=a

csr:
	openssl ecparam -name prime256v1 -genkey -noout -out $(NAME).key
	openssl req -new -key $(NAME).key -nodes -out $(NAME).csr -sha384 \
		-subj "/CN=its not validated for now"

sign:
	openssl x509 -req -days 360 -in $(NAME).csr -CA ca.cert -CAkey ca.key \
		-CAcreateserial -out $(NAME).cert
