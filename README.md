# ca.py
OpenSSL CA(Certificate Authority) 생성 및 인증서(Certification) 생성 도구

## 프로그램 소개
데비안 리눅스에 포함되어 있는 OpenSSL 인증서 생성을 도와주는 스크립트인 CA.pl 파일의 파이썬 버전이며, 기존 CA.pl에 있던 오류를
수정하고 인증서 생성 요청시 인증서 디렉터리 등을 따로 지정할 수 있도록 했습니다.

## 인증기관 생성
인증 기관을 생성하는 명령으로서 실행시 CATOP의 위치(설정 파일 혹은 커맨드 옵션 지정)에 인증 기관 파일을 생성합니다.

```sh
# ca.py --newca
```

## 신규 인증서 생성
클라이언트 인증서를 생성하는 명령으로서 프로그램 실행 위치에 신규 인증서를 생성합니다. newkey.pem, newreq.pem 파일이 만들어집니다.
인증서 파일 이름을 변경할 수 있는 기능은 추후 제공 예정입니다.

```sh
$ ca.py --newreq
```

## 인증서 사인
인증기관의 인증서로 클라이언트 인증서(newreq.pem)을 인증해주는 기능입니다. 실행 결과로 newcert.pem 파일이 만들어집니다.

```sh
# ca.py --sign
```

## 인증기관 생성에 필요한 추가 옵션
이 프로그램은 기본적으로 데비안 리눅스 기반에서 동작하도록 설계되어 있습니다. 단, 다른 배포본에서도 사용할 수 있도록 인증기관 디렉터리
와 인증기관 파일 이름과 인증서 유효기간을 추가로 지정할 수 있습니다.

추가 옵션 전달은 인증기관 설정 파일 혹은 커맨드 옵션으로 전달할 수 있으며, 인증기관 설정 파일과 커맨드 옵션은 같이 사용할 수 없습니다.

### 인증기관 설정 파일
인증기관 설정 파일은 INI 타입의 파일로 작성하며 [CA] 섹션이 존재해야 합니다. 설정할 수 있는 엔트리는 CATOP, DAYS, CADAYS, CAKEY,
CAREQ, CACERT가 있습니다. 아래와 같이 지정하며 신규 인증기관 생성시에 같이 사용할 수 있습니다.

```sh
# ca.py -i ca.ini
# ca.py --config ca.ini
```

### 인증기관 설정 커맨드 옵션 제공
인증기관 설정 파일을 사용하지 않고 사용할 경우 사용합니다. 인증기관 생성시 같이 제공할 수 있습니다.

```sh
# ca.py -d 10  # 클라이언트 인증서 유효기간(10일)
# ca.py --days 10  # 클라이언트 인증서 유효기간(10일)

# ca.py --cadays 365 # 인증기관 인증서의 유효기간(1년)

# ca.py --catop=/etc/ssl/ca # 인증기관 인증서 디렉터리(클라이언트 서명 데이터도 함께 보관)
# ca.py --cakey=cakey.pem # 인증기관 인증서 비밀키 파일명
# ca.py --careq=careq.pem # 인증기관 인증서 서명 요청 파일
# ca.py --cacert=cacert.pem # 인증기관 인증서로 서명이 완료된 인증서 파일(브라우저에 배포 필요)
```

## ca.py 실행 결과
```sh
usage: ca.py [-h]
             [--newca | --newcert | --newreq | --newreq-nodes | --pkcs12 Certification Name | --xsign |
              --sign | --signcert certfile keyfile | --signCA | --verify [cert.pem [cert.pem ...]]]
             [-i filename] [-d days] [--cadays days]
             [--catop ca_top_directory] [--cakey ca_key_filename]
             [--careq ca_request_filename] [--cacert ca_certficate_filename]

optional arguments:
  -h, --help            show this help message and exit
  --newca               New Certificate Authority
  --newcert             New Certification
  --newreq              New Certification CSR
  --newreq-nodes        New Certification Nodes
  --pkcs12 Certification Name
                        PKCS12
  --xsign               Certification xsign
  --sign, --signreq     Certification sign
  --signcert certfile keyfile
                        Certification Sign
  --signCA              CA sign
  --verify [cert.pem [cert.pem ...]]
                        Certification Verify
  -i filename, --config filename
                        Location of the CA.ini file to be used for issuing
                        certificates
  -d days, --days days  Client Certificate Validity Period
  --cadays days         Root Certification Authority Certificate Validity
                        Period
  --catop ca_top_directory
                        Certification Authority Directory
  --cakey ca_key_filename
                        Certificate authority secret key filename
  --careq ca_request_filename
                        Certificate authority authentication request key
                        filename
  --cacert ca_certficate_filename
                        Certificate Authority Key File Name
```