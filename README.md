# Run stuff

Setup kind and all infra, I haven't tried spicedb at all.
Port-forwading probably don't work.

```shell
sh setup-kind-infra.sh
```

Build the microservceis and load them to kind

```shell
make load-all
```

Apply microservices

```shell
kubectl apply -f service-a/deployment.yaml
kubectl apply -f service-b/deployment.yaml
```

Spire

I don't think we need to register any spire worklodas.
I think the helm chart does it for us.

Look in the logs for more info

```shell
k logs spire-server-0 spire-controller-manager |grep app/sa
```

## Verify service-a -> b

Exec into `service-a` and use `http` endpoint for easy testing

```shell
wget --no-check-certificate http://service-a:8081/hello -O -
wget --no-check-certificate http://service-a:8081/call-b -O -
```
