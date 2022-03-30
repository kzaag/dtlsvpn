
OPTS=-Wall -Wpedantic -pedantic -Wextra -Werror -lssl -lcrypto -lpthread
FILES=main.c
OUT=bin/vpn

build:
	mkdir -p bin
	@gcc $(FILES) $(OPTS) -o $(OUT)

build-asan:
	@gcc -g -fsanitize=address $(FILES) $(OPTS) -o $(OUT)

ca:
	openssl ecparam -name prime256v1 -genkey -noout -out ca.key
	openssl req -x509 -key ca.key -out ca.cert -sha384 \
		-days 180 -sha384 -nodes -subj "/CN=ca.com"

NAME=a

csr:
	openssl ecparam -name prime256v1 -genkey -noout -out $(NAME).key
	openssl req -new -key $(NAME).key -nodes -out $(NAME).csr -sha384 \
		-subj "/CN=its not validated for now"

sign:
	openssl x509 -req -days 360 -in $(NAME).csr -CA ca.cert -CAkey ca.key \
		-CAcreateserial -out $(NAME).cert

allcert:
	$(MAKE) ca
	
	$(MAKE) csr NAME=client
	$(MAKE) csr NAME=server

	$(MAKE) sign NAME=client
	$(MAKE) sign NAME=server

NETNS_NAME=vpns
VETH_INITNS=vpnveth
VETH_NETNS=veth0
VETH_NETNS_A=172.30.2.6
VETH_NETNS_M=/30
VETH_INITNS_A=172.30.2.5
VETH_INITNS_M=/30

ARPTABLES=arptables-nft
IPTABLES=iptables

netns:
	ip netns add $(NETNS_NAME)
	ip link add $(VETH_INITNS) type veth peer name $(VETH_NETNS)
	ip link set $(VETH_NETNS) netns $(NETNS_NAME)

	ip netns exec $(NETNS_NAME) \
		ip a a $(VETH_NETNS_A)$(VETH_NETNS_M) dev $(VETH_NETNS)
	ip netns exec $(NETNS_NAME) ip link set $(VETH_NETNS) up

	ip a a $(VETH_INITNS_A)$(VETH_NETNS_M) dev $(VETH_INITNS)
	ip link set $(VETH_INITNS) up

	$(IPTABLES) -A INPUT -i $(VETH_INITNS) -j ACCEPT
	$(ARPTABLES) -A INPUT -i $(VETH_INITNS) -j ACCEPT
	$(ARPTABLES) -A OUTPUT -o $(VETH_INITNS) -j ACCEPT

netns-rollback:
	ip netns del $(NETNS_NAME) || :
	ip link del $(VETH_INITNS) || :
	$(IPTABLES) -D INPUT -i $(VETH_INITNS) -j ACCEPT || :
	$(ARPTABLES) -D INPUT -i $(VETH_INITNS) -j ACCEPT || :
	$(ARPTABLES) -D OUTPUT -o $(VETH_INITNS) -j ACCEPT || :

netns-client:
	cd bin && ip netns exec $(NETNS_NAME) ./vpn -c \
		-C ../client.cert 	\
		-K ../client.key  	\
		-A ../ca.cert     	\
		-h $(VETH_INITNS_A) 	\
		-p 3456			\
		-n tun0			\
		-a 10.1.2.230/30	

netns-server:
	cd bin && ./vpn -s \
		-C ../server.cert 	\
		-K ../server.key  	\
		-A ../ca.cert     	\
		-h $(VETH_INITNS_A) 	\
		-p 3456			\
		-n tun0			\
		-a 10.1.2.229/30

google-routes:
	@curl -s "https://www.gstatic.com/ipranges/goog.json" | \
	 	jq -r '.prefixes[].ipv4Prefix | select(. != null)' | \
		xargs printf "ip route add \"%s\" dev tun0\n" > add-google-routes.sh
	@awk "\$$1==\"nameserver\" {print \$$2}" /etc/resolv.conf | \
		xargs printf "ip route add %s/32 dev tun0\n" >> add-google-routes.sh
	@sed 's/add/delete/g' add-google-routes.sh > delete-google-routes.sh

	
add-google-routes:
	ip netns exec $(NETNS_NAME) bash add-google-routes.sh
