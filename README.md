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
kubectl port-forward -n authentik svc/authentik-server 9000:80 &
username: akadmin
password: PleaseGenerateASecureKey
```

## Testing OIDC Flow

To test the OIDC authentication and authorization flow, you'll need to:

### 3. Test OIDC Authentication via Service-A

Service-A now includes OIDC functionality and can authenticate users to call service-b. You can test this by exec'ing into the service-a pod:

```shell
kubectl exec -it deployment/service-a -- /bin/sh
```

#### Test user login and get token

```shell
# Login as alice and get her OIDC token
wget --post-data="username=alice&password=testpassword123" http://localhost:8081/login -O -

# Login as bob and get his OIDC token  
wget --post-data="username=bob&password=testpassword123" http://localhost:8081/login -O -
```

#### Test service-to-service calls with user authentication

```shell
# Service-A authenticates alice and calls service-b with her token
wget "http://localhost:8081/call-b-user?username=alice&password=testpassword123" -O -

# Service-A authenticates bob and calls service-b with his token
wget "http://localhost:8081/call-b-user?username=bob&password=testpassword123" -O -
```

#### Test document operations with user authentication

```shell
# Alice tries to view document 1 (should work - alice has full access)
wget "http://localhost:8081/documents/user?username=alice&password=testpassword123&id=doc1&operation=view" -O -

# Alice tries to edit document 1 (should work - alice has edit access)
wget "http://localhost:8081/documents/user?username=alice&password=testpassword123&id=doc1&operation=edit" -O -

# Alice tries to delete document 1 (should work - alice has delete access)
wget "http://localhost:8081/documents/user?username=alice&password=testpassword123&id=doc1&operation=delete" -O -

# Bob tries to delete document 2 (should fail - bob only has view/edit on doc2)
wget "http://localhost:8081/documents/user?username=bob&password=testpassword123&id=doc2&operation=delete" -O -

# Bob tries to view document 3 (should work - bob has view access)
wget "http://localhost:8081/documents/user?username=bob&password=testpassword123&id=doc3&operation=view" -O -

# Bob tries to edit document 3 (should fail - bob only has view on doc3)
wget "http://localhost:8081/documents/user?username=bob&password=testpassword123&id=doc3&operation=edit" -O -
```

### 4. Expected behavior

- **Without OIDC token**: Service-b will work with mTLS only, showing service identity but no user information
- **With valid OIDC token**: Service-b will authenticate the user and show username/email from the token
- **With invalid token**: Service-b will return 401 Unauthorized for protected endpoints
- **Authorization**: Different users have different permissions on documents based on SpiceDB policies

### 5. Service-A New Endpoints

Service-A now includes these OIDC-enabled endpoints:

- `POST /login` - Get OIDC token for a user (form data: username, password)
- `GET /call-b-user` - Authenticate user and call service-b (query params: username, password)  
- `GET /documents/user` - Authenticate user and perform document operations (query params: username, password, id, operation)

## spicedb

For some reason spicedb can't handle spiffie id standard of `spiffie://-org-`, insttead we have to use `spiffie-org`.
Sow we will have to write some kind of middelware in the code that does that translation all the time.
