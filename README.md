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
