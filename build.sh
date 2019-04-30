rm -r -f CS-API
rm -r -f api
rm -r -f general

git clone https://github.com/CREDITSCOM/CS-API
mkdir api
mkdir general
thrift -gen js -out .\api .\CS-API\api.thrift
thrift -gen js -out .\general .\CS-API\general.thrift
