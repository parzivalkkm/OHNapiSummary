package hust.cse.ohnapisummary.env.funcs.nubers;

import com.bai.env.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.env.funcs.NAPIFunctionBase;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;
import hust.cse.ohnapisummary.util.NAPIValueManager;
import hust.cse.ohnapisummary.util.TypeCategory;

import java.util.List;
import java.util.Set;

public class NapiCreateNumberFunction extends NAPIFunctionBase {
    public NapiCreateNumberFunction() {
        super(Set.of(
                // napi_status napi_create_double(napi_env env, double value, napi_value* result);
                "napi_create_double",

                // napi_status napi_create_int32(napi_env env, int32_t value, napi_value* result);
                "napi_create_int32",

                // napi_status napi_create_uint32(napi_env env, uint32_t value, napi_value* result);
                "napi_create_uint32",

                // napi_status napi_create_int64(napi_env env, int64_t value, napi_value* result);
                "napi_create_int64",

                //NAPI_EXTERN napi_status napi_create_bigint_int64(napi_env env,
                //                                                 int64_t value,
                //                                                 napi_value* result);
                "napi_create_bigint_int64",

                //NAPI_EXTERN napi_status napi_create_bigint_uint64(napi_env env,
                //                                                  uint64_t value,
                //                                                  napi_value* result);
                "napi_create_bigint_uint64"

        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {

        NAPIValue callNV = recordCall(context, calleeFunc); // 记录调用的nv
        // 处理返回值
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        KSet retKset = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_STATUS, calleeFunc.getEntryPoint(), callNV, retALoc.getLen()* 8, calleeFunc, context, inOutEnv);
        inOutEnv.set(retALoc, retKset, true);

        // 向result中插入一个抽象值
        List<ALoc> alocs = getParamALocs(calleeFunc, 2, inOutEnv);

        NAPIValue localNV = recordLocal(context, calleeFunc, 2);
        KSet kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize*8, calleeFunc, context, inOutEnv);

        for (ALoc loc: alocs) {
            KSet ks = inOutEnv.get(loc);
            for (AbsVal val : ks) {
                ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                inOutEnv.set(ptr, kSetForValue, true);
            }
        }


    }
}
