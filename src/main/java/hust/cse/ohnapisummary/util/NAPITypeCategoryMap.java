package hust.cse.ohnapisummary.util;

import java.util.HashMap;
import java.util.Map;

public class NAPITypeCategoryMap {
    private static final Map<String, Map<Integer, TypeCategory>> napiTypeMapIn = new HashMap<>();



    static {

        // 参数相关

        napiTypeMapIn.put("napi_get_cb_info", new HashMap<>());
        napiTypeMapIn.get("napi_get_cb_info").put(0, TypeCategory.NAPI_ENV);
        napiTypeMapIn.get("napi_get_cb_info").put(1, TypeCategory.NAPI_CALLBACK_INFO);
        napiTypeMapIn.get("napi_get_cb_info").put(2, TypeCategory.NUMBER);

        // 数字相关

        napiTypeMapIn.put("napi_create_int32", new HashMap<>());
        napiTypeMapIn.get("napi_create_int32").put(0, TypeCategory.NAPI_ENV);
        napiTypeMapIn.get("napi_create_int32").put(1, TypeCategory.NUMBER);

        napiTypeMapIn.put("napi_create_uint32", new HashMap<>());
        napiTypeMapIn.get("napi_create_uint32").put(0, TypeCategory.NAPI_ENV);
        napiTypeMapIn.get("napi_create_uint32").put(1, TypeCategory.NUMBER);

        napiTypeMapIn.put("napi_create_int64", new HashMap<>());
        napiTypeMapIn.get("napi_create_int64").put(0, TypeCategory.NAPI_ENV);
        napiTypeMapIn.get("napi_create_int64").put(1, TypeCategory.NUMBER);

        napiTypeMapIn.put("napi_create_double", new HashMap<>());
        napiTypeMapIn.get("napi_create_double").put(0, TypeCategory.NAPI_ENV);
        napiTypeMapIn.get("napi_create_double").put(1, TypeCategory.NUMBER);

        napiTypeMapIn.put("napi_get_value_int32", new HashMap<>());
        napiTypeMapIn.get("napi_get_value_int32").put(0, TypeCategory.NAPI_ENV);
        napiTypeMapIn.get("napi_get_value_int32").put(1, TypeCategory.NAPI_VALUE);

        napiTypeMapIn.put("napi_get_value_uint32", new HashMap<>());
        napiTypeMapIn.get("napi_get_value_uint32").put(0, TypeCategory.NAPI_ENV);
        napiTypeMapIn.get("napi_get_value_uint32").put(1, TypeCategory.NAPI_VALUE);

        napiTypeMapIn.put("napi_get_value_int64", new HashMap<>());
        napiTypeMapIn.get("napi_get_value_int64").put(0, TypeCategory.NAPI_ENV);
        napiTypeMapIn.get("napi_get_value_int64").put(1, TypeCategory.NAPI_VALUE);

        napiTypeMapIn.put("napi_get_value_double", new HashMap<>());
        napiTypeMapIn.get("napi_get_value_double").put(0, TypeCategory.NAPI_ENV);
        napiTypeMapIn.get("napi_get_value_double").put(1, TypeCategory.NAPI_VALUE);

        // BOOL相关

        // 字符串相关

    }

    private static final Map<String, Map<Integer, TypeCategory>> napiTypeMapOut = new HashMap<>();

    static {

        // 参数相关

        napiTypeMapOut.put("napi_get_cb_info", new HashMap<>());
        napiTypeMapOut.get("napi_get_cb_info").put(2, TypeCategory.NUMBER);
        napiTypeMapOut.get("napi_get_cb_info").put(3, TypeCategory.NAPI_VALUE);
        napiTypeMapOut.get("napi_get_cb_info").put(4, TypeCategory.NAPI_VALUE);
        napiTypeMapOut.get("napi_get_cb_info").put(5, TypeCategory.BUFFER);

        // 数字相关

        napiTypeMapIn.put("napi_create_int32", new HashMap<>());
        napiTypeMapIn.get("napi_create_int32").put(2, TypeCategory.NAPI_VALUE);

        napiTypeMapIn.put("napi_create_uint32", new HashMap<>());
        napiTypeMapIn.get("napi_create_uint32").put(2, TypeCategory.NAPI_VALUE);

        napiTypeMapIn.put("napi_create_int64", new HashMap<>());
        napiTypeMapIn.get("napi_create_int64").put(2, TypeCategory.NAPI_VALUE);

        napiTypeMapIn.put("napi_create_double", new HashMap<>());
        napiTypeMapIn.get("napi_create_double").put(2, TypeCategory.NAPI_VALUE);

        napiTypeMapIn.put("napi_get_value_int32", new HashMap<>());
        napiTypeMapIn.get("napi_get_value_int32").put(2, TypeCategory.NUMBER);

        napiTypeMapIn.put("napi_get_value_uint32", new HashMap<>());
        napiTypeMapIn.get("napi_get_value_uint32").put(2, TypeCategory.NUMBER);

        napiTypeMapIn.put("napi_get_value_int64", new HashMap<>());
        napiTypeMapIn.get("napi_get_value_int64").put(2, TypeCategory.NUMBER);

        napiTypeMapIn.put("napi_get_value_double", new HashMap<>());
        napiTypeMapIn.get("napi_get_value_double").put(2, TypeCategory.NUMBER);

        // BOOL相关



        // 字符串相关

    }


    public static TypeCategory getNAPIType(String napiName, int index, boolean isInput) {
        if (isInput) {
            if (napiTypeMapIn.containsKey(napiName) && napiTypeMapIn.get(napiName).containsKey(index)) {
                return napiTypeMapIn.get(napiName).get(index);
            }
        } else {
            if (napiTypeMapOut.containsKey(napiName) && napiTypeMapOut.get(napiName).containsKey(index)) {
                return napiTypeMapOut.get(napiName).get(index);
            }
        }
        return TypeCategory.UNKNOWN;

    }


}
