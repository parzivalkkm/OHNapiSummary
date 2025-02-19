package hust.cse.ohnapisummary.util;

import com.bai.util.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;

import javax.xml.crypto.Data;

public enum TypeCategory {
    // 不透明的值
    IN_TRANSPARENT,
    NAPI_STATUS,
    NAPI_ENV,
    NAPI_CALLBACK_INFO,
    NAPI_VALUE,
    UNKNOWN,
    NUMBER,
    BUFFER,

    ;

    public static TypeCategory byName(DataType dt) {
        DataType originalDt = dt;
        TypeCategory ret;
        ret = handleIterTypedef(dt);
        if (ret != null && ret != UNKNOWN) {
            return ret;
        }
        // Non java type
        // skip TypeDef TODO enum?
        if (dt instanceof TypeDef) {
            dt = ((TypeDef) dt).getBaseDataType();
        }
        ret = handleType(dt.getName());
        if (ret != null) {
            return ret;
        }
        if (originalDt.getName().equals("undefined")) {
            return UNKNOWN;
        }
        if (originalDt instanceof Pointer || dt instanceof Pointer) {
            if (originalDt.getName().contains("napi_value")) {
                return NAPI_VALUE;
            }
            return BUFFER;
        }
        Logging.error("[TypeCategory] Unknown return type: " + originalDt.getName());
        return UNKNOWN;
    }

    private static TypeCategory handleNAPIType(String dataTypeName){
        switch (dataTypeName.replaceAll("\\s+", "")) {
            case "napi_status":
                return NAPI_STATUS;
            case "napi_value":
                return NAPI_VALUE;
            case "napi_callback_info":
                return NAPI_CALLBACK_INFO;
            case "napi_env":
                return NAPI_ENV;
            default:
                return null;
        }
    }

    private static TypeCategory handleIterTypedef(DataType dt) {
        // 递归检测
        do {
            TypeCategory tc = handleNAPIType(dt.getName());
            if (tc != UNKNOWN) {
                return tc;
            }
            if (dt instanceof TypeDef) {
                dt = ((TypeDef) dt).getDataType();
            }
        } while(dt instanceof TypeDef);
        return handleNAPIType(dt.getName());
    }

    private static TypeCategory handleType(String cTypeName) {
        switch (cTypeName.replaceAll("\\s+", "")) {
            case "char":
            case "short":
            case "int":
            case "long":
            case "uint":
            case "ulong":
            case "float":
            case "double":
                return NUMBER;
            case "char*":
                return BUFFER;
            case "void*":
                return UNKNOWN;
            default:
                return null;
        }
    }

}
