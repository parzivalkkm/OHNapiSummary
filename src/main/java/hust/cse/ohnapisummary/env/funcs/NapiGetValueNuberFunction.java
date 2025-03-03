package hust.cse.ohnapisummary.env.funcs;

import com.bai.env.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;
import hust.cse.ohnapisummary.util.NAPIValueManager;
import hust.cse.ohnapisummary.util.TypeCategory;

import java.util.List;
import java.util.Map;
import java.util.Set;

public class NapiGetValueNuberFunction extends NAPIFunctionBase{

    public NapiGetValueNuberFunction() {
        super(Set.of(
                //NAPI_EXTERN napi_status napi_get_value_double(napi_env env,
                //                                              napi_value value,
                //                                              double* result);
                "napi_get_value_double",

                // napi_status napi_get_value_int32(napi_env env, napi_value value, int32_t* result);
                "napi_get_value_int32",

                // napi_status napi_get_value_int64(napi_env env, napi_value value, int64_t* result);
                "napi_get_value_int64",

                //        napi_status napi_get_value_uint32(napi_env env, napi_value value, uint32_t* result);
                "napi_get_value_uint32",

                //NAPI_EXTERN napi_status napi_get_value_bigint_int64(napi_env env,
                //                                                    napi_value value,
                //                                                    int64_t* result,
                //                                                    bool* lossless);
                "napi_get_value_bigint_int64",

                //NAPI_EXTERN napi_status napi_get_value_bigint_uint64(napi_env env,
                //                                                     napi_value value,
                //                                                     uint64_t* result,
                //                                                     bool* lossless);
                "napi_get_value_bigint_uint64"



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
        // 记录这个返回值
        NAPIValue localNV = recordLocal(context, calleeFunc,2);

        int size = typeSizeMap.get(calleeFunc.getName());
        // 向分析中写入一个抽象值
        KSet kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NUMBER, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize* 8, calleeFunc, context, inOutEnv);
        for (ALoc loc: alocs) {
            KSet ks = inOutEnv.get(loc);
            for (AbsVal val : ks) {
                ALoc ptr = toALoc(val, size);
                inOutEnv.set(ptr, kSetForValue, true); // *ptr = env
            }
        }

        if(calleeFunc.getName().equals("napi_get_value_bigint_int64") || calleeFunc.getName().equals("napi_get_value_bigint_uint64")){
            // 向lossless中插入一个抽象值
            alocs = getParamALocs(calleeFunc, 3, inOutEnv);
            // 记录这个返回值
            localNV = recordLocal(context, calleeFunc,3);
            // 向分析中写入一个抽象值 bool也认为是数字
            kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NUMBER, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize* 8, calleeFunc, context, inOutEnv);
            for (ALoc loc: alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, kSetForValue, true); // *ptr = env
                }
            }
        }


    }

    // TODO: 真的需要区分宽度吗？
    Map<String, Integer> typeSizeMap = Map.of(
        "napi_get_value_double", 8,
        "napi_get_value_int32", 4,
        "napi_get_value_int64", 8,
        "napi_get_value_uint32", 4,
        "napi_get_value_bigint_int64", 8,
        "napi_get_value_bigint_uint64", 8
    );

}
