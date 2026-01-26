import socket as s
import threading
import rsa
from cryptography.fernet import Fernet

rsaMaxSize = 64
rsaEncryptedSize = 64 + 11
publicKey, privateKey = rsa.newkeys(rsaEncryptedSize * 8)
publicKeyBytes = publicKey.save_pkcs1(format = "DER")

newClients = []

parsePacketFunctionsFromNames = {}
parsePacketFunctionTypeSignatures = {}
writePacketFunctions = []
writePacketFunctionTypeSignatures = {}

class Connection:
    def __init__(self, socket, address, port):
        self.socket = socket
        self.address = address
        self.port = port
        self.key = None
        self.fernet = None
        
        self.parsePacketFunctions = []

        self.lock = threading.Lock()
        self.active = True

        self.toSend = []

    def setKey(self, key):
        self.key = key
        self.fernet = Fernet(key)

    def recvN(self, n):
        if not self.active:
            return
        data = b""
        while len(data) < n:
            try:
                data += self.socket.recv(n - len(data))
            except Exception as e:
                print(e)
                self.close()
                return
        return data

    def recieveRaw(self):
        if not self.active:
            return
        if data := self.recvN(4):
            messageSize = int.from_bytes(data)
            if (data := self.recvN(messageSize)) != None:
                data = self.fernet.decrypt(data)
                return data
        self.close()

    def recieve(self):
        if (data := self.recieveRaw()) != None:
            while data:
                size, data = int.from_bytes(data[:4]), data[4:]
                packet, data = data[:size], data[size:]
                packetType, packetData = parseInt(packet)
                if packetType >= len(self.parsePacketFunctions):
                    raise Exception(f"Packet type id {packetType} outside range (must be from 0 to {len(self.parsePacketFunctions) - 1})")
                self.parsePacketFunctions[packetType](packetData)
            return
        self.close()

    def recievePacketTypes(self):
        if (data := self.recieveRaw()) != None:
            typeInfo, data = parseList((str, str), data)
            packetTypeInfo, data = parseList((str, str), data)
            for info in typeInfo:
                name = info[0]
                if not name in parseTypesFromNames:
                    raise Exception(f"No local parseable type named \"{name}\"")
                t = parseTypesFromNames[name]
                if parseFunctionTypeSignatures[t] != info[1]:
                    raise Exception(f"Mismatching type signatures for parsing {name}, local is {parseFunctionTypeSignatures[t]}, remote is {info[1]}")
            for info in packetTypeInfo:
                name = info[0]
                if not name in parsePacketFunctionsFromNames:
                    raise Exception(f"No local packet type named \"{name}\"")
                t = parsePacketFunctionsFromNames[name]
                if parsePacketFunctionTypeSignatures[t] != info[1]:
                    raise Exception(f"Mismatching type signatures for packet type {name}, local is {parsePacketFunctionTypeSignatures[t]}, remote is {info[1]}")
                self.parsePacketFunctions.append(t)
            return
        self.close()

    def sendRaw(self, message):
        try:
            encrypted = self.fernet.encrypt(message)
            self.socket.sendall(len(encrypted).to_bytes(4) + encrypted)
        except Exception as e:
            print(e)
            self.close()
            return

    def send(self):
        if not self.active:
            return
        message = b""
        while self.toSend:
            packet = self.toSend.pop(0)
            message += len(packet).to_bytes(4) + packet
        self.sendRaw(message)

    def sendPacketTypes(self):
        message = writeList((str, str), list(map(lambda t: (t.__name__, writeFunctionTypeSignatures[t]), writeFunctionTypesToCheck)))
        message += writeList((str, str), list(map(lambda t: (t.__name__[5:], writePacketFunctionTypeSignatures[t]), writePacketFunctions)))
        self.sendRaw(message)

    def close(self, silent = False):
        if not self.active:
            return
        self.active = False
        if not silent:
            print("Closing connection to " + str(self.address) + ":" + str(self.port))
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except:
            pass
        self.socket.close()

def listener(port, password):
    listenerSocket = s.socket()
    listenerSocket.bind(("", port))
    listenerSocket.listen(1)
    while True:
        socket, (address, port) = listenerSocket.accept()
        connection = Connection(socket, address, port)
        try:
            socket.settimeout(0.1)
            remotePublicKey = rsa.PublicKey.load_pkcs1(connection.recvN(len(publicKeyBytes)), format = "DER")
            socket.sendall(publicKeyBytes)
            passwordGuess = rsa.decrypt(connection.recvN(rsaEncryptedSize), privateKey)
            if passwordGuess != password.encode():
                new.close(silent = True)
                continue
            socket.settimeout(None)
            symmetricKey = Fernet.generate_key()
            socket.sendall(rsa.encrypt(symmetricKey, remotePublicKey))
            connection.setKey(symmetricKey)
            connection.recievePacketTypes()
            connection.sendPacketTypes()
            newClients.append(connection)
        except Exception as e:
            print(e)
            connection.close(silent = True)

def listen(port, authKey):
    thread = threading.Thread(target = listener, args = (port, authKey), daemon = True)
    thread.start()
    return thread

def connect(address, port, password):
    if len(password.encode()) > rsaMaxSize:
        return
    socket = s.socket()
    try:
        socket.connect((address, port))
        connection = Connection(socket, address, port)
        socket.sendall(publicKeyBytes)
        remotePublicKey = rsa.PublicKey.load_pkcs1(connection.recvN(len(publicKeyBytes)), format = "DER")
        socket.sendall(rsa.encrypt(password.encode(), remotePublicKey))
        symmetricKey = rsa.decrypt(connection.recvN(rsaEncryptedSize), privateKey)
        connection.setKey(symmetricKey)
        connection.sendPacketTypes()
        connection.recievePacketTypes()
        return connection
    except Exception as e:
        print(e)
        print(f"Failed to connect to {address}:{port}")
        socket.close()

def typeToStr(t):
    if type(t) == list and len(t) == 1:
        return f"[{typeToStr(t[0])}]"
    elif type(t) == tuple:
        return f"({",".join(map(typeToStr, t))})"
    try:
        return t.__name__
    except:
        raise Exception(f"Unrecognized type \"{t}\" in typeToStr")

intSize = 4
intOffset = 2 ** (intSize * 8 - 1)

def parseInt(data):
    if len(data) < intSize:
        raise Exception("parse too few bytes")
    return int.from_bytes(data[:intSize]) - intOffset, data[intSize:]

def writeInt(n):
    return (n + intOffset).to_bytes(intSize)

def parseBool(data):
    if len(data) < 1:
        raise Exception("parse too few bytes")
    return bool(data[0]), data[1:]

def writeBool(b):
    return b.to_bytes(1)

def parseBytes(data):
    size, data = parseInt(data)
    if len(data) < size:
        raise Exception("parse too few bytes")
    return data[:size], data[size:]

def writeBytes(bs):
    return writeInt(len(bs)) + bs

def parseString(data):
    bs, data = parseBytes(data) 
    return bs.decode(), data

def writeString(s):
    return writeBytes(s.encode())

parseFunctions = {
    int : parseInt,
    bool : parseBool,
    bytes : parseBytes,
    str : parseString
}
parseTypesFromNames = {}
parseFunctionTypeSignatures = {}

writeFunctions = {
    int : writeInt,
    bool : writeBool,
    bytes : writeBytes,
    str : writeString
}
writeFunctionTypesToCheck = []
writeFunctionTypeSignatures = {}

def parseList(t, data):
    size, data = parseInt(data)
    l = []
    for i in range(size):
        result, data = parse(t, data)
        l.append(result)
    return l, data

def writeList(t, l):
    data = writeInt(len(l))
    for x in l:
        data += write(t, x)
    return data

def parse(t, data):
    if type(t) == list and len(t) == 1:
        return parseList(t[0], data)
    elif type(t) == tuple:
        return tuple((result := parse(t2, data), data := result[1])[0][0] for t2 in t), data
    elif t in parseFunctions:
        return parseFunctions[t](data)
    print(f"Unrecognized parse type \"{t}\"")

def write(t, x):
    if type(t) == list and len(t) == 1:
        return writeList(t[0], x)
    elif type(t) == tuple:
        return b"".join(write(t[i], x[i]) for i in range(len(t)))
    elif t in writeFunctions:
        return writeFunctions[t](x)
    print(f"Unrecognized write type \"{t}\"")

def parseFunction(*types):
    def decorator(f):
        def _f(data):
            parsedArgs = []
            for argType in types:
                parsedArg, data = parse(argType, data)
                parsedArgs.append(parsedArg)
            return f(*parsedArgs), data
        _f.__name__ = f.__name__
        return _f
    return decorator

def writeFunction(*types):
    def decorator(f):
        def _f(*args, **kwargs):
            xs = f(*args, **kwargs)
            if len(xs) != len(types):
                print(f"Mismatching list sizes between {types} and {xs} in function {f.__name__}")
                return
            data = b""
            for i in range(len(types)):
                data += write(types[i], xs[i])
            return data
        _f.__name__ = f.__name__
        return _f
    return decorator

def parseable(*types):
    def decorator(cls):
        cls.parse = parseFunction(*types)(cls.parse)
        parseFunction[cls] = cls.parse
        parseTypesFromNames[cls.__name__] = cls
        parseFunctionTypeSignatures[cls] = ",".join(map(typeToStr, types))
        return cls
    return decorator

def writeable(*types):
    def decorator(cls):
        cls.write = writeFunction(*types)(cls.write)
        writeFunctions[cls] = cls.write
        writeFunctionTypesToCheck.append(cls)
        writeFunctionTypeSignatures[cls] = ",".join(map(typeToStr, types))
        return cls
    return decorator

def parseWriteable(*types):
    def decorator(cls):
        cls = parseable(*types)(cls)
        cls = writeable(*types)(cls)
        return cls
    return decorator

def parsePacket(*types):
    def decorator(f):
        if f.__name__[:5] != "parse":
            raise Exception(f"Invalid parsePacket function name \"{f.__name__}\", should begin with \"parse\"")
        f = parseFunction(*types)(f)
        def _f(data):
            try:
                f(data)
            except Exception as e:
                if e.args == ("parse too few bytes",):
                    raise Exception(f"Insufficient bytes {data} for {f.__name__}")
                else:
                    raise e
        _f.__name__ = f.__name__
        if _f.__name__ in parsePacketFunctionsFromNames:
            raise Exception(f"Duplicate parsePacket function name {_f.__name__}")
        parsePacketFunctionsFromNames[_f.__name__[5:]] = _f
        parsePacketFunctionTypeSignatures[_f] = ",".join(map(typeToStr, types))
        return _f
    return decorator

def writePacket(*types, method = False):
    def decorator(f):
        if f.__name__[:5] != "write":
            raise Exception(f"Invalid writePacket function name \"{f.__name__}\", should begin with \"write\"")
        f = writeFunction(*types)(f)
        id = len(writePacketFunctions)
        if method:
            def _f(self, connection, *args, **kwargs):
                if type(connection) != Connection:
                    raise Exception(f"Invalid connection passed to {f.__name__}")
                connection.toSend.append(writeInt(id) + f(self, *args, **kwargs))
        else:
            def _f(connection, *args, **kwargs):
                if type(connection) != Connection:
                    raise Exception(f"Invalid connection passed to {f.__name__}")
                connection.toSend.append(writeInt(id) + f(*args, **kwargs))
        _f.__name__ = f.__name__
        writePacketFunctions.append(_f)
        writePacketFunctionTypeSignatures[_f] = ",".join(map(typeToStr, types))
        writePacketFunctions.append(_f)
        return _f
    return decorator

def withId(*types):
    def decorator(cls):
        cls.all = {}
        cls.nextId = 0
        old__init__ = cls.__init__
        def __init__(self, *args, id = None, **kwargs):
            if id != None:
                if id in cls.all:
                    raise Exception(f"Invalid local initialization, {cls.__name__} object with id {id} already exists")
                self.id = id
            else:
                while cls.nextId in cls.all:
                    cls.nextId += 1
                self.id = cls.nextId
                cls.nextId += 1
            old__init__(self, *args, **kwargs)
            cls.all[self.id] = self
        cls.__init__ = __init__
        if "parseInit" in dir(cls):
            oldParseInit = cls.parseInit
            def parseInit(id, *args):
                if id in cls.all:
                    raise Exception(f"Invalid remote initialization, {cls.__name__} object with id {id} already exists")
                x = cls.__new__(cls)
                x.id = id
                oldParseInit(x, *args)
                cls.all[id] = x
            parseInit.__name__ += cls.__name__
            cls.parseInit = parsePacket(int, *types)(parseInit)
            def parseDel(id):
                x = cls.all[id]
                if id in cls.all:
                    del cls.all[id]
                else:
                    raise Exception(f"Invalid deletion, no {cls.__name__} object with id {id}")
                if "onDel" in dir(cls):
                    x.onDel()
            parseDel.__name__ += cls.__name__
            cls.parseDel = parsePacket(int)(parseDel)
        if "writeInit" in dir(cls):
            oldWriteInit = cls.writeInit
            def writeInit(self):
                return self.id, *oldWriteInit(self)
            writeInit.__name__ += cls.__name__
            cls.writeInit = writePacket(int, *types, method = True)(writeInit)
            def writeDel(self):
                return (self.id,)
            writeDel.__name__ += cls.__name__
            cls.writeDel = writePacket(int, method = True)(writeDel)
        def parse(id):
            if id in cls.all:
                return cls.all[id]
            raise Exception(f"Invalid parsing, no {cls.__name__} object with id {id}")
        parse.__name__ += cls.__name__
        cls.parse = parseFunction(int)(parse)
        parseFunctions[cls] = cls.parse
        parseTypesFromNames[cls.__name__] = cls
        parseFunctionTypeSignatures[cls] = "int"
        def write(self):
            return (self.id,)
        write.__name__ += cls.__name__
        cls.write = writeFunction(int)(write)
        writeFunctions[cls] = cls.write
        writeFunctionTypesToCheck.append(cls)
        writeFunctionTypeSignatures[cls] = "int"
        return cls
    return decorator
