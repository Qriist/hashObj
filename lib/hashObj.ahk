#Requires AutoHotkey v2.0
#Module hashObj
#include <Aris/Qriist/hash> ; github:Qriist/hash@18302f1 --main hash.ahk
#include <Aris/Qriist/GetFilePathFromFileObject> ; github:Qriist/GetFilePathFromFileObject@f2169b9 --main Lib\GetFilePathFromFileObject.ahk
#Import hash {*}
#Import GetFilePathFromFileObject {*}

Export Default hashObj(inObj, nohash := 0, resultArr := [], ptrMap := Map(), top := 1) {

    static para := {
        Object: { Start: "Object{", End: "}" },
        Map: { Start: "Map(", End: ")" },
        Array: { Start: "Array[", End: "]" },
        Buffer: { Start: "Buffer|", End: "|" },
        File: { Start: 'File"', End: '"' },
        Null: { Start: "Null<", End: ">" }
    }

    ; ;safe return
    if !IsObject(inObj)
        return hash(&inObj, "SHA512")

    ;catch circular references
    ptr := ObjPtr(inObj)
    if ptrMap.Has(ptr)
        return resultArr.push("DEREF")
    ptrMap[ptr] := 1

    ;define how objects get serialized
    inType := Type(inObj)
    parastart := (para.HasProp(inType) ? para.%inType%.Start : inType "*")
    paraend := (para.HasProp(inType) ? para.%inType%.End : "*")

    switch inType {
        case "Null":
            resultArr.Push(parastart)  ;object open
            resultArr.Push("+x00::NULL=")
            resultArr.Push(paraend)    ;object close
        Default:
            resultArr.Push(parastart)  ;object open

            ; process .properties
            for k, v in inObj.OwnProps() {
                if IsObject(v) {

                    resultArr.Push("." k ":")
                    hashObj(v, nohash, resultArr, ptrMap, 0)
                } else {
                    ; val := (!nohash ? hash(&v,) : v)
                    val := (!nohash ? hash(&v, "SHA512") : nohash = 1 ? v : hash(&v, "SHA512"))
                    switch Type(v) {
                        case "Integer":
                            resultArr.Push("." k ":!:" val "=")
                        case "Float":
                            resultArr.Push("." k ":@:" val "=")
                        case "String":
                            resultArr.Push("." k ":" StrPut(v) ":" val "=")
                    }
                }
            }

            ; process ["keys"]
            if InObj.HasProp("__Item") {
                for k, v in inObj {
                    if IsObject(v) {
                        resultArr.Push("/" k ":")
                        hashObj(v, nohash, resultArr, ptrMap, 0)
                    } else
                        val := (!nohash ? hash(&v, "SHA512") : nohash = 1 ? v : hash(&v, "SHA512"))
                    switch Type(v) {
                        case "Integer":
                            resultArr.Push("/" k ":!:" val "=")
                        case "Float":
                            resultArr.Push("/" k ":@:" val "=")
                        case "String":
                            resultArr.Push("/" k ":" StrPut(v) ":" val "=")
                    }
                }
            }

            ;get the meat of Buffer and File objects
            switch inType {
                case "Buffer":
                    val := (!nohash ? hash(&inObj, "SHA512") : nohash = 1 ? "[BUFFER]" : hash(&inObj, "SHA512"))
                    resultArr.Push("+" inobj.size ":|:" val "=")
                case "File":
                    hashfile := GetFilePathFromFileObject(inObj)
                    hashfile := FileOpen(hashfile, "r")
                    val := (!nohash ? hash(&hashfile, "SHA512") : nohash = 1 ? "[FILE]" : hash(&inObj, "SHA512"))
                    resultArr.Push("+" hashfile.Length ":-:" val "=")
            }

            resultArr.Push(paraend)    ;object close
    }

    ; prevent sub objects from finalizing
    if !top
        return ""

    ;export
    concat := ""
    VarSetStrCapacity(&concat, resultArr.Length * 256)
    for k, v in resultArr
        concat .= v

    if nohash
        return concat
    return hash(&concat, "SHA512")
}