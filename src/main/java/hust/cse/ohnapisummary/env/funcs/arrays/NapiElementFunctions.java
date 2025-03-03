package hust.cse.ohnapisummary.env.funcs.arrays;

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

public class NapiElementFunctions extends NAPIFunctionBase {
    public NapiElementFunctions() {
        super(Set.of(
            //NAPI_EXTERN napi_status napi_set_element(napi_env env,
            //                                         napi_value object,
            //                                         uint32_t index,
            //                                         napi_value value);
            "napi_set_element",  // 仅记录即可

            //NAPI_EXTERN napi_status napi_has_element(napi_env env,
            //                                         napi_value object,
            //                                         uint32_t index,
            //                                         bool* result);
            "napi_has_element",

            //NAPI_EXTERN napi_status napi_get_element(napi_env env,
            //                                         napi_value object,
            //                                         uint32_t index,
            //                                         napi_value* result);
            "napi_get_element",

            //NAPI_EXTERN napi_status napi_delete_element(napi_env env,
            //                                            napi_value object,
            //                                            uint32_t index,
            //                                            bool* result);
            "napi_delete_element"

        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {

        NAPIValue callNV = recordCall(context, calleeFunc); // 记录调用的nv
        // 处理返回值
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        KSet retKset = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_STATUS, calleeFunc.getEntryPoint(), callNV, retALoc.getLen()* 8, calleeFunc, context, inOutEnv);
        inOutEnv.set(retALoc, retKset, true);

        if(calleeFunc.getName().equals("napi_has_element")||calleeFunc.getName().equals("napi_delete_element")) {

            List<ALoc> alocs = getParamALocs(calleeFunc, 3, inOutEnv);
            NAPIValue localNV = recordLocal(context, calleeFunc, 3);
            KSet kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NUMBER, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize* 8, calleeFunc, context, inOutEnv);
            for (ALoc loc: alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, kSetForValue, true); // *ptr = env
                }
            }
        } else if(calleeFunc.getName().equals("napi_get_element")) {
            // 向result中插入一个抽象值
            List<ALoc> alocs = getParamALocs(calleeFunc, 3, inOutEnv);
            // 记录这个返回值
            NAPIValue localNV = recordLocal(context, calleeFunc, 3);
            // 向分析中写入一个抽象值
            KSet kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
            for (ALoc loc : alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, kSetForValue, true); // *ptr = env
                }
            }

        }
    }
}
