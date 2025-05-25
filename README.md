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

### Testing Document Operations

You can test the document operations with different permissions. Service-a has endpoints to interact with service-b's document API.

#### Document 1 (Full Access - View, Edit, Delete)

```shell
# View document 1
wget --no-check-certificate http://service-a:8081/documents/view?id=doc1 -O -

# Edit document 1
wget --no-check-certificate http://service-a:8081/documents/edit?id=doc1 -O -

# Delete document 1
wget --no-check-certificate http://service-a:8081/documents/delete?id=doc1 -O -
```

#### Document 2 (View and Edit Only)

```shell
# View document 2
wget --no-check-certificate http://service-a:8081/documents/view?id=doc2 -O -

# Edit document 2
wget --no-check-certificate http://service-a:8081/documents/edit?id=doc2 -O -

# Delete document 2 (should fail with 403 Forbidden)
wget --no-check-certificate http://service-a:8081/documents/delete?id=doc2 -O -
```

#### Document 3 (View Only)

```shell
# View document 3
wget --no-check-certificate http://service-a:8081/documents/view?id=doc3 -O -

# Edit document 3 (should fail with 403 Forbidden)
wget --no-check-certificate http://service-a:8081/documents/edit?id=doc3 -O -

# Delete document 3 (should fail with 403 Forbidden)
wget --no-check-certificate http://service-a:8081/documents/delete?id=doc3 -O -
```

## Authentik setup

To login

```shell
username: akadmin
password: PleaseGenerateASecureKey
```

## spicedb

For some reason spicedb can't handle spiffie id standard of `spiffie://-org-`, insttead we have to use `spiffie-org`.
Sow we will have to write some kind of middelware in the code that does that translation all the time.
