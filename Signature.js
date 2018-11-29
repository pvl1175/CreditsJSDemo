
function Signature(Param) {
    var DefParam = {
        Id: 0,
        PublicKey: "",
        PrivateKey: "",
        PublickTo: "",
        AmountIntegral: 0,
        Smart: null
    };

    for (var i in DefParam) {
        if (Param[i] == undefined) {
            Param[i] = DefParam[i];
        }
    }

    if (Param.PublicKey.length != 44)
        return null;
    if (Param.PrivateKey.length < 87 || Param.PrivateKey.length > 88)
        return null;
    if (Param.PublickTo.length != 44)
        return null;



    var PublickFrom = Base58.decode(Param.PublicKey);
    var PrivateKey = Base58.decode(Param.PrivateKey);
    var PublickTo = Base58.decode(Param.PublickTo);

    var am = new Amount({
        integral: Param.AmountIntegral,
        fraction: 0
    });

    var bl = new Amount({
        integral: 0,
        fraction: 0
    });

    var Smart;
    var NumbByte = 101;

    if (Param.Smart == null) {
        Smart = new Uint8Array(0);
    } else {
        Smart = SmatToByte(Param.Smart);
        NumbByte += Smart.length + 4;
    }

    var StrSign = new Uint8Array(NumbByte);

    StrSign[7] = 0;

    var SumT = GetBitArray(Param.Id, 4);
    for (var index in SumT) {
        StrSign[Number(index)] = SumT[Number(index)];
    }

    for (var index in PublickFrom) {
        StrSign[8 + Number(index)] = PublickFrom[index];
    }

    for (var index in PublickTo) {
        StrSign[40 + Number(index)] = PublickTo[index];
    }

    var SumT = GetBitArray(am.integral, 4);

    for (var index in SumT) {
        StrSign[72 + Number(index)] = SumT[Number(index)];
    }

    var SumT = GetBitArray(bl.integral, 4);

    for (var index in SumT) {
        StrSign[84 + Number(index)] = SumT[Number(index)];
    }

    StrSign[96] = 1;

    if (Smart.length > 0) {

        StrSign[97] = 1;

        var SumT = GetBitArray(Smart.length, 4);

        for (var index in SumT) {
            StrSign[101 + Number(index)] = SumT[Number(index)];
        }

        for (var index in Smart) {
            StrSign[105 + Number(index)] = Smart[Number(index)];
        }
    }

    return nacl.sign.detached(StrSign, PrivateKey);
}



function SmatToByte(Obj) {

    var SourceCode;
    var L = 0;
    if (Obj.sourceCode != undefined) {
        L = Obj.sourceCode.length;
    }
    SourceCode = new Uint8Array(7 + L);
    SourceCode[0] = 11;
    SourceCode[1] = 0;
    SourceCode[2] = 1;
    if (Obj.sourceCode != undefined) {

        var ArStr = getBytes(Obj.sourceCode.length);
        for (var k in ArStr) {
            SourceCode[3 + Number(k)] = ArStr[k];
        }

        for (var k in Obj.sourceCode) {
            SourceCode[7 + Number(k)] = Obj.sourceCode[k].charCodeAt();
        }
    }

    var ByteCode;
    var L = 0;
    if (Obj.byteCode != undefined) {
        L = Obj.byteCode.length;
    }
    ByteCode = new Uint8Array(7 + L);
    ByteCode[0] = 11;
    ByteCode[1] = 0;
    ByteCode[2] = 2;
    if (Obj.byteCode != undefined) {

        var ArStr = getBytes(Obj.byteCode.length);
        for (var k in ArStr) {
            ByteCode[3 + Number(k)] = ArStr[k];
        }

        for (var k in Obj.byteCode) {
            ByteCode[7 + Number(k)] = Obj.byteCode[k].charCodeAt();
        }
    }

    var HashState;
    var L = 0;
    if (Obj.hashState != undefined) {
        L = Obj.hashState.length;
    }
    HashState = new Uint8Array(7 + L);
    HashState[0] = 11;
    HashState[1] = 0;
    HashState[2] = 3;
    if (Obj.hashState != undefined) {


        HashState[3] = 0;
        HashState[4] = 0;
        HashState[5] = 0;
        HashState[6] = 32;

        for (var k in Obj.hashState) {
            HashState[7 + Number(k)] = Obj.hashState[k].charCodeAt();
        }
    }

    var Method;
    if (Obj.method != undefined) {
        Method = new Uint8Array(7 + Obj.method.length);
        Method[0] = 11;
        Method[1] = 0;
        Method[2] = 4;

        var ArStr = getBytes(Obj.method.length);

        for (var k in ArStr) {
            Method[3 + Number(k)] = ArStr[k];
        }

        for (var k in Obj.method) {
            Method[7 + Number(k)] = Obj.method[k].charCodeAt();
        }
    }

    var Params;
    var Leng = 8;
    if (Obj.params != undefined) {
        for (var k in Obj.params) {
            Leng += Obj.params[k].length + 4;
        }

        Params = new Uint8Array(Leng);
        Params[0] = 15;
        Params[1] = 0;
        Params[2] = 5;
        Params[3] = 11;

        var ArStr = getBytes(Obj.params.length);
        for (var k in ArStr) {
            Params[4 + Number(k)] = ArStr[k];
        }

        var index = 8;
        for (var k in Obj.params) {
            for (var j in Obj.params[k]) {

                var ArStr = getBytes(Obj.params[k].length);
                for (var ck in ArStr) {
                    Params[index + Number(ck)] = ArStr[ck];
                }

                Params[index + 4 + Number(j)] = Obj.params[k][j].charCodeAt();
            }
            index += 4 + 1 + Number(j);
        }
    }

    var ForgetNewState;
    ForgetNewState = new Uint8Array(4);
    ForgetNewState[0] = 2;
    ForgetNewState[1] = 0;
    ForgetNewState[2] = 6;
    if (Obj.forgetNewState != undefined && Obj.forgetNewState) {
        if (Obj.forgetNewState) {
            ForgetNewState[3] = 1;
        }
    }
    
    var SourceCodeLength = 0;
    var ByteCodeLength = 0;
    var HashStateLength = 0;
    var MethodLength = 0;
    var ParamsLenght = 0;
    var ForgetNewStateLength = 0;


    if (SourceCode != undefined) {
        SourceCodeLength = SourceCode.length;
    }
    if (ByteCode != undefined) {
        ByteCodeLength = ByteCode.length;
    }
    if (HashState != undefined) {
        HashStateLength = HashState.length;
    }
    if (Method != undefined) {
        MethodLength = Method.length;
    }
    if (Params != undefined) {
        ParamsLenght = Leng;
    }
    if (ForgetNewState != undefined) {
        ForgetNewStateLength = ForgetNewState.length;
    }

    var Res = new Uint8Array(SourceCodeLength + ByteCodeLength + HashStateLength + MethodLength + ParamsLenght + ForgetNewStateLength + 1);

    if (SourceCode != undefined) {
        for (var k in SourceCode) {
            Res[0 + Number(k)] = SourceCode[k];
        }
    }

    if (ByteCode != undefined) {
        for (var k in ByteCode) {
            Res[SourceCodeLength + Number(k)] = ByteCode[k];
        }
    }

    if (HashState != undefined) {
        for (var k in HashState) {
            Res[SourceCodeLength + ByteCodeLength + Number(k)] = HashState[k];
        }
    }

    if (Method != undefined) {
        for (var k in Method) {
            Res[SourceCodeLength + ByteCodeLength + HashStateLength + Number(k)] = Method[k];
        }
    }

    if (Params != undefined) {
        for (var k in Params) {
            Res[SourceCodeLength + ByteCodeLength + HashStateLength + MethodLength + Number(k)] = Params[k];
        }
    }

    if (ForgetNewState != undefined) {
        for (var k in ForgetNewState) {
            Res[SourceCodeLength + ByteCodeLength + HashStateLength + MethodLength + ParamsLenght + Number(k)] = ForgetNewState[k];
        }
    }

    return Res;
}

function GetBitArray(n, i) {
    var Ar = new Uint8Array(i);

    for (var index in Ar) {
        Ar[index] = index > 0 ? (n >> index * 8) & 0xFF : n & 0xFF;
    }

    return Ar;
}

// Generated by CoffeeScript 1.8.0
(function () {
    var ALPHABET, ALPHABET_MAP, Base58, i;

    Base58 = (typeof module !== "undefined" && module !== null ? module.exports : void 0) || (window.Base58 = {});

    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    ALPHABET_MAP = {};

    i = 0;

    while (i < ALPHABET.length) {
        ALPHABET_MAP[ALPHABET.charAt(i)] = i;
        i++;
    }

    Base58.encode = function (buffer) {
        var carry, digits, j;
        if (buffer.length === 0) {
            return "";
        }
        i = void 0;
        j = void 0;
        digits = [0];
        i = 0;
        while (i < buffer.length) {
            j = 0;
            while (j < digits.length) {
                digits[j] <<= 8;
                j++;
            }
            digits[0] += buffer[i];
            carry = 0;
            j = 0;
            while (j < digits.length) {
                digits[j] += carry;
                carry = (digits[j] / 58) | 0;
                digits[j] %= 58;
                ++j;
            }
            while (carry) {
                digits.push(carry % 58);
                carry = (carry / 58) | 0;
            }
            i++;
        }
        i = 0;
        while (buffer[i] === 0 && i < buffer.length - 1) {
            digits.push(0);
            i++;
        }
        return digits.reverse().map(function (digit) {
            return ALPHABET[digit];
        }).join("");
    };

    Base58.decode = function (string) {
        var bytes, c, carry, j;
        if (string.length === 0) {
            return new (typeof Uint8Array !== "undefined" && Uint8Array !== null ? Uint8Array : Buffer)(0);
        }
        i = void 0;
        j = void 0;
        bytes = [0];
        i = 0;
        while (i < string.length) {
            c = string[i];
            if (!(c in ALPHABET_MAP)) {
                throw "Base58.decode received unacceptable input. Character '" + c + "' is not in the Base58 alphabet.";
            }
            j = 0;
            while (j < bytes.length) {
                bytes[j] *= 58;
                j++;
            }
            bytes[0] += ALPHABET_MAP[c];
            carry = 0;
            j = 0;
            while (j < bytes.length) {
                bytes[j] += carry;
                carry = bytes[j] >> 8;
                bytes[j] &= 0xff;
                ++j;
            }
            while (carry) {
                bytes.push(carry & 0xff);
                carry >>= 8;
            }
            i++;
        }
        i = 0;
        while (string[i] === "1" && i < string.length - 1) {
            bytes.push(0);
            i++;
        }
        return new (typeof Uint8Array !== "undefined" && Uint8Array !== null ? Uint8Array : Buffer)(bytes.reverse());
    };

}).call(this);
