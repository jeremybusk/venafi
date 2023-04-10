#!/bin/bash
set -eu
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <cert path>"
  echo "Example: $0 \"MyFolder\Subfolder\mycert1\""
  exit
fi
cert_path=$1

shopt -s expand_aliases
alias scurl="curl -sS -b cookies.txt -c cookies.txt -H 'Content-type: application/json' -H 'Accept: application/json'"

json=$(cat <<-EOF
  {
    "client_id":"$CLIENT_ID",
    "username":"${USERNAME}",
    "password":"${PASSWORD}",
    "scope":"${SCOPE}"
  }
EOF
)
rsp=$(scurl -X POST https://$API_HOST/vedauth/authorize/oauth -d "${json}")
token=$(echo "$rsp" | jq -r .access_token)

get_crt_via_guid(){
  url="https://${API_HOST}/vedsdk/certificates/{${guid}}"
  rsp=$(scurl -H "Authorization:Bearer ${token}" "$url" | jq)
  echo "$rsp"
}

search_crt(){
  # GET https://test.venafi.example/vedsdk/certificates/?parentdnrecursive=%5CVED%5CPolicy&limit=2&offset=0
  # Authorization:Bearer 4MyGeneratedBearerTknz==
  url="https://${API_HOST}/vedsdk/certificates/?parentdnrecursive=%5CVED%5CPolicy&limit=2&offset=0"
  rsp=$(scurl -H "Authorization:Bearer ${token}" "$url" | jq)
  echo "$rsp"
}


get_crt_via_dn(){
  url="https://$API_HOST/vedsdk/Certificates/Retrieve"

  # folder is cert path in all properties
  cert_path=$(echo $cert_path | sed 's/\\/\\\\/g')
  cert_prefix="\VED\Policy\Certificates\\"
  cert_prefix=$(echo $cert_prefix | sed 's/\\/\\\\/g')
  cert_dn="${cert_prefix}${cert_path}"

  json=$(cat <<-EOF
    {
      "CertificateDN":"${cert_dn}",
      "Format":"Base64",
      "IncludeChain":"true",
      "RootFirstOrder":"true"
    }
EOF
)

  rsp=$(scurl -H "Authorization:Bearer ${token}" -d "$json" "$url")

  echo "$rsp" | jq -r .CertificateData | base64 -d
}

get_crt_via_dn
