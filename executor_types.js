//
// Autogenerated by Thrift Compiler (0.11.0)
//
// DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
//


APIResponse = function(args) {
  this.code = null;
  this.message = null;
  this.contractState = null;
  this.ret_val = null;
  this.contractVariables = null;
  if (args) {
    if (args.code !== undefined && args.code !== null) {
      this.code = args.code;
    }
    if (args.message !== undefined && args.message !== null) {
      this.message = args.message;
    }
    if (args.contractState !== undefined && args.contractState !== null) {
      this.contractState = args.contractState;
    }
    if (args.ret_val !== undefined && args.ret_val !== null) {
      this.ret_val = new Variant(args.ret_val);
    }
    if (args.contractVariables !== undefined && args.contractVariables !== null) {
      this.contractVariables = Thrift.copyMap(args.contractVariables, [Variant]);
    }
  }
};
APIResponse.prototype = {};
APIResponse.prototype.read = function(input) {
  input.readStructBegin();
  while (true)
  {
    var ret = input.readFieldBegin();
    var fname = ret.fname;
    var ftype = ret.ftype;
    var fid = ret.fid;
    if (ftype == Thrift.Type.STOP) {
      break;
    }
    switch (fid)
    {
      case 1:
      if (ftype == Thrift.Type.BYTE) {
        this.code = input.readByte().value;
      } else {
        input.skip(ftype);
      }
      break;
      case 2:
      if (ftype == Thrift.Type.STRING) {
        this.message = input.readString().value;
      } else {
        input.skip(ftype);
      }
      break;
      case 3:
      if (ftype == Thrift.Type.STRING) {
        this.contractState = input.readBinary().value;
      } else {
        input.skip(ftype);
      }
      break;
      case 4:
      if (ftype == Thrift.Type.STRUCT) {
        this.ret_val = new Variant();
        this.ret_val.read(input);
      } else {
        input.skip(ftype);
      }
      break;
      case 5:
      if (ftype == Thrift.Type.MAP) {
        var _size0 = 0;
        var _rtmp34;
        this.contractVariables = {};
        var _ktype1 = 0;
        var _vtype2 = 0;
        _rtmp34 = input.readMapBegin();
        _ktype1 = _rtmp34.ktype;
        _vtype2 = _rtmp34.vtype;
        _size0 = _rtmp34.size;
        for (var _i5 = 0; _i5 < _size0; ++_i5)
        {
          if (_i5 > 0 ) {
            if (input.rstack.length > input.rpos[input.rpos.length -1] + 1) {
              input.rstack.pop();
            }
          }
          var key6 = null;
          var val7 = null;
          key6 = input.readString().value;
          val7 = new Variant();
          val7.read(input);
          this.contractVariables[key6] = val7;
        }
        input.readMapEnd();
      } else {
        input.skip(ftype);
      }
      break;
      default:
        input.skip(ftype);
    }
    input.readFieldEnd();
  }
  input.readStructEnd();
  return;
};

APIResponse.prototype.write = function(output) {
  output.writeStructBegin('APIResponse');
  if (this.code !== null && this.code !== undefined) {
    output.writeFieldBegin('code', Thrift.Type.BYTE, 1);
    output.writeByte(this.code);
    output.writeFieldEnd();
  }
  if (this.message !== null && this.message !== undefined) {
    output.writeFieldBegin('message', Thrift.Type.STRING, 2);
    output.writeString(this.message);
    output.writeFieldEnd();
  }
  if (this.contractState !== null && this.contractState !== undefined) {
    output.writeFieldBegin('contractState', Thrift.Type.STRING, 3);
    output.writeBinary(this.contractState);
    output.writeFieldEnd();
  }
  if (this.ret_val !== null && this.ret_val !== undefined) {
    output.writeFieldBegin('ret_val', Thrift.Type.STRUCT, 4);
    this.ret_val.write(output);
    output.writeFieldEnd();
  }
  if (this.contractVariables !== null && this.contractVariables !== undefined) {
    output.writeFieldBegin('contractVariables', Thrift.Type.MAP, 5);
    output.writeMapBegin(Thrift.Type.STRING, Thrift.Type.STRUCT, Thrift.objectLength(this.contractVariables));
    for (var kiter8 in this.contractVariables)
    {
      if (this.contractVariables.hasOwnProperty(kiter8))
      {
        var viter9 = this.contractVariables[kiter8];
        output.writeString(kiter8);
        viter9.write(output);
      }
    }
    output.writeMapEnd();
    output.writeFieldEnd();
  }
  output.writeFieldStop();
  output.writeStructEnd();
  return;
};

MethodDescription = function(args) {
  this.name = null;
  this.argTypes = null;
  this.returnType = null;
  if (args) {
    if (args.name !== undefined && args.name !== null) {
      this.name = args.name;
    }
    if (args.argTypes !== undefined && args.argTypes !== null) {
      this.argTypes = Thrift.copyList(args.argTypes, [null]);
    }
    if (args.returnType !== undefined && args.returnType !== null) {
      this.returnType = args.returnType;
    }
  }
};
MethodDescription.prototype = {};
MethodDescription.prototype.read = function(input) {
  input.readStructBegin();
  while (true)
  {
    var ret = input.readFieldBegin();
    var fname = ret.fname;
    var ftype = ret.ftype;
    var fid = ret.fid;
    if (ftype == Thrift.Type.STOP) {
      break;
    }
    switch (fid)
    {
      case 1:
      if (ftype == Thrift.Type.STRING) {
        this.name = input.readString().value;
      } else {
        input.skip(ftype);
      }
      break;
      case 2:
      if (ftype == Thrift.Type.LIST) {
        var _size10 = 0;
        var _rtmp314;
        this.argTypes = [];
        var _etype13 = 0;
        _rtmp314 = input.readListBegin();
        _etype13 = _rtmp314.etype;
        _size10 = _rtmp314.size;
        for (var _i15 = 0; _i15 < _size10; ++_i15)
        {
          var elem16 = null;
          elem16 = input.readString().value;
          this.argTypes.push(elem16);
        }
        input.readListEnd();
      } else {
        input.skip(ftype);
      }
      break;
      case 3:
      if (ftype == Thrift.Type.STRING) {
        this.returnType = input.readString().value;
      } else {
        input.skip(ftype);
      }
      break;
      default:
        input.skip(ftype);
    }
    input.readFieldEnd();
  }
  input.readStructEnd();
  return;
};

MethodDescription.prototype.write = function(output) {
  output.writeStructBegin('MethodDescription');
  if (this.name !== null && this.name !== undefined) {
    output.writeFieldBegin('name', Thrift.Type.STRING, 1);
    output.writeString(this.name);
    output.writeFieldEnd();
  }
  if (this.argTypes !== null && this.argTypes !== undefined) {
    output.writeFieldBegin('argTypes', Thrift.Type.LIST, 2);
    output.writeListBegin(Thrift.Type.STRING, this.argTypes.length);
    for (var iter17 in this.argTypes)
    {
      if (this.argTypes.hasOwnProperty(iter17))
      {
        iter17 = this.argTypes[iter17];
        output.writeString(iter17);
      }
    }
    output.writeListEnd();
    output.writeFieldEnd();
  }
  if (this.returnType !== null && this.returnType !== undefined) {
    output.writeFieldBegin('returnType', Thrift.Type.STRING, 3);
    output.writeString(this.returnType);
    output.writeFieldEnd();
  }
  output.writeFieldStop();
  output.writeStructEnd();
  return;
};

GetContractMethodsResult = function(args) {
  this.code = null;
  this.message = null;
  this.methods = null;
  if (args) {
    if (args.code !== undefined && args.code !== null) {
      this.code = args.code;
    }
    if (args.message !== undefined && args.message !== null) {
      this.message = args.message;
    }
    if (args.methods !== undefined && args.methods !== null) {
      this.methods = Thrift.copyList(args.methods, [MethodDescription]);
    }
  }
};
GetContractMethodsResult.prototype = {};
GetContractMethodsResult.prototype.read = function(input) {
  input.readStructBegin();
  while (true)
  {
    var ret = input.readFieldBegin();
    var fname = ret.fname;
    var ftype = ret.ftype;
    var fid = ret.fid;
    if (ftype == Thrift.Type.STOP) {
      break;
    }
    switch (fid)
    {
      case 1:
      if (ftype == Thrift.Type.BYTE) {
        this.code = input.readByte().value;
      } else {
        input.skip(ftype);
      }
      break;
      case 2:
      if (ftype == Thrift.Type.STRING) {
        this.message = input.readString().value;
      } else {
        input.skip(ftype);
      }
      break;
      case 3:
      if (ftype == Thrift.Type.LIST) {
        var _size18 = 0;
        var _rtmp322;
        this.methods = [];
        var _etype21 = 0;
        _rtmp322 = input.readListBegin();
        _etype21 = _rtmp322.etype;
        _size18 = _rtmp322.size;
        for (var _i23 = 0; _i23 < _size18; ++_i23)
        {
          var elem24 = null;
          elem24 = new MethodDescription();
          elem24.read(input);
          this.methods.push(elem24);
        }
        input.readListEnd();
      } else {
        input.skip(ftype);
      }
      break;
      default:
        input.skip(ftype);
    }
    input.readFieldEnd();
  }
  input.readStructEnd();
  return;
};

GetContractMethodsResult.prototype.write = function(output) {
  output.writeStructBegin('GetContractMethodsResult');
  if (this.code !== null && this.code !== undefined) {
    output.writeFieldBegin('code', Thrift.Type.BYTE, 1);
    output.writeByte(this.code);
    output.writeFieldEnd();
  }
  if (this.message !== null && this.message !== undefined) {
    output.writeFieldBegin('message', Thrift.Type.STRING, 2);
    output.writeString(this.message);
    output.writeFieldEnd();
  }
  if (this.methods !== null && this.methods !== undefined) {
    output.writeFieldBegin('methods', Thrift.Type.LIST, 3);
    output.writeListBegin(Thrift.Type.STRUCT, this.methods.length);
    for (var iter25 in this.methods)
    {
      if (this.methods.hasOwnProperty(iter25))
      {
        iter25 = this.methods[iter25];
        iter25.write(output);
      }
    }
    output.writeListEnd();
    output.writeFieldEnd();
  }
  output.writeFieldStop();
  output.writeStructEnd();
  return;
};

