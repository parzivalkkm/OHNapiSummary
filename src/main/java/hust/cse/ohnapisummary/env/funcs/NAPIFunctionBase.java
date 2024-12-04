package hust.cse.ohnapisummary.env.funcs;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;

import java.util.Set;

public class NAPIFunctionBase extends ExternalFunctionBase {

    public static Address currentCallSite;

    private static final Set<String> staticSymbols = Set.of(
            // 注册相关函数
            "napi_define_properties",
            "napi_module_register",
            // 参数读取相关函数
            "napi_get_cb_info",
            // 值的get
//            "napi_get_undefined",
//            "napi_get_null",
//            "napi_get_boolean",
//            "napi_get_global",

            "napi_get_value_double",
            "napi_get_value_int32",
            "napi_get_value_uint32",
            "napi_get_value_int64",
            "napi_get_value_bool",
            // 值的create
            "napi_create_double",
            "napi_create_int32",
            "napi_create_uint32",
            "napi_create_int64",

            // string的get
            "napi_get_value_string_latin1",
            "napi_get_value_string_utf8",
            "napi_get_value_string_utf16",

            // string的create
            "napi_create_string_latin1",
            "napi_create_string_utf8",
            "napi_create_string_utf16"
    );

    public NAPIFunctionBase() {
        super(staticSymbols);
    }

    @Override
    public void defineDefaultSignature(Function callFunction) {
    }

    public NAPIFunctionBase(Set<String> symbols) {
        super(symbols);
    }

    public static NAPIValue recordCall(Context ctx, Function api) {
        NAPIValue nv = new NAPIValue(ctx, api, currentCallSite.getOffset());
        MyGlobalState.napiManager.registerCall(nv, ctx);
        return nv;
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
        String funcName = calleeFunc.getName();
        KSet ret = null;
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        if (funcName.equals("napi_define_properties")) {
            NAPIValue nv = recordCall(context, calleeFunc);
        } else if (funcName.equals("napi_module_register")) {

        } else if (funcName.equals("napi_get_cb_info")) {


            // 获取 napi_value
        } else if (funcName.equals("napi_get_value_double")) {
            NAPIValue nv = recordCall(context, calleeFunc);
        } else if (funcName.equals("napi_get_value_int32")) {

        } else if (funcName.equals("napi_get_value_uint32")) {

        } else if (funcName.equals("napi_get_value_int64")) {

        } else if (funcName.equals("napi_get_value_bool")) {

            // 创建 napi_value
        } else if (funcName.equals("napi_create_double")) {
            NAPIValue nv = recordCall(context, calleeFunc);
        } else if (funcName.equals("napi_create_int32")) {

        } else if (funcName.equals("napi_create_uint32")) {

        }


        if (ret != null) {
            inOutEnv.set(retALoc, ret, true);
        }
    }
}
