rmdir /S /Q build64
rmdir /S /Q CS-API
rmdir /S /Q thrift
rmdir /S /Q api
rmdir /S /Q general

git clone https://github.com/CREDITSCOM/CS-API
mkdir api
mkdir general
thrift.exe -gen js -out .\api .\CS-API\api.thrift
thrift.exe -gen js -out .\general .\CS-API\general.thrift
