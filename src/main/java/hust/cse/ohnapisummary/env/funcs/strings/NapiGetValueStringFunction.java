package hust.cse.ohnapisummary.env.funcs.strings;

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

public class NapiGetValueStringFunction extends NAPIFunctionBase {

    public NapiGetValueStringFunction() {
        super(Set.of(
                // napi_status napi_get_value_string_utf8(napi_env env,
                //                                       napi_value value,
                //                                       char* buf,
                //                                       size_t bufsize,
                //                                       size_t* result);
                "napi_get_value_string_utf8",

                //NAPI_EXTERN napi_status napi_get_value_string_latin1(napi_env env,
                //                                                     napi_value value,
                //                                                     char* buf,
                //                                                     size_t bufsize,
                //                                                     size_t* result);
                "napi_get_value_string_latin1",

                //NAPI_EXTERN napi_status napi_get_value_string_utf16(napi_env env,
                //                                                    napi_value value,
                //                                                    char16_t* buf,
                //                                                    size_t bufsize,
                //                                                    size_t* result);
                "napi_get_value_string_utf16"
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {

        NAPIValue callNV = recordCall(context, calleeFunc); // 记录调用的nv
        // 处理返回值
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        KSet retKset = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_STATUS, calleeFunc.getEntryPoint(), callNV, retALoc.getLen()* 8, calleeFunc, context, inOutEnv);
        inOutEnv.set(retALoc, retKset, true);

        // 向buf写入
        // TODO buffer 应该是什么都不用做

//        List<ALoc> alocs = getParamALocs(calleeFunc, 2, inOutEnv);
//
//        NAPIValue localNV = recordLocal(context, calleeFunc,2);
//        KSet env = NAPIValueManager.getKSetForValue(TypeCategory.BUFFER, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize* 8, calleeFunc, context, inOutEnv);
//        for (ALoc loc: alocs) {
//            KSet ks = inOutEnv.get(loc);
//            for (AbsVal val : ks) {
//                ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
//                inOutEnv.set(ptr, env, true);
//            }
//        }

//        List<ALoc> alocs = getParamALocs(calleeFunc, 2, inOutEnv);
//        // TODO 如果传入的是null，那就没有必要记录了
////        if (alocs.size() == 0) {
////            return;
////        }
//        NAPIValue localNV = recordLocal(context, calleeFunc,2);
//        // TODO 不是number 暂且标记为不透明值吧
//        KSet setForValue = NAPIValueManager.getKSetForValue(TypeCategory.IN_TRANSPARENT, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize* 8, calleeFunc, context, inOutEnv);
//        for (ALoc loc: alocs) {
//            KSet ks = inOutEnv.get(loc);
//            for (AbsVal val : ks) {
//                ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
//                inOutEnv.set(ptr, setForValue, true);
//            }
//        }

        List<ALoc>  alocs = getParamALocs(calleeFunc, 4, inOutEnv);

        NAPIValue localNV = recordLocal(context, calleeFunc,4);
        KSet setForValue = NAPIValueManager.getKSetForValue(TypeCategory.NUMBER, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize* 8, calleeFunc, context, inOutEnv);
        for (ALoc loc: alocs) {
            KSet ks = inOutEnv.get(loc);
            for (AbsVal val : ks) {
                ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                inOutEnv.set(ptr, setForValue, true);
            }
        }




    }
}
