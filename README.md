A small DNS server that NXDOMAINs anything in the blocklist
```
curl -XPOST -H 'Content-Type: application/json' http://localhost:8080/blocklist # -d '{"domain_name": "gooogle.ads.com" }'
curl -XGET -H 'Content-Type: application/json' http://localhost:8080/blocklist
```
