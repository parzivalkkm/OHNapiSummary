package hust.cse.ohnapisummary.env.funcs.buffer;

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

public class NapiBufferFunction extends NAPIFunctionBase {
    public NapiBufferFunction() {
        super(Set.of(
            // NAPI_EXTERN napi_status napi_create_buffer(napi_env env,
            //                                           size_t length,
            //                                           void** data,
            //                                           napi_value* result);
            "napi_create_buffer",               //	创建并获取一个指定大小的JS Buffer。

            //NAPI_EXTERN napi_status napi_create_buffer_copy(napi_env env,
            //                                                size_t length,
            //                                                const void* data,
            //                                                void** result_data,
            //                                                napi_value* result);
            "napi_create_buffer_copy",          //	创建并获取一个指定大小的JS Buffer，并以给定数据进行初始化。

            //NAPI_EXTERN napi_status napi_create_external_buffer(napi_env env,
            //                                                    size_t length,
            //                                                    void* data,
            //                                                    napi_finalize finalize_cb,
            //                                                    void* finalize_hint,  // TODO 这个回调怎么处理。。。
            //                                                    napi_value* result);
            "napi_create_external_buffer",      //	创建并获取一个指定大小的JS Buffer，并以给定数据进行初始化，该接口可为Buffer附带额外数据。

            //NAPI_EXTERN napi_status napi_get_buffer_info(napi_env env,
            //                                             napi_value value,
            //                                             void** data,
            //                                             size_t* length);
            "napi_get_buffer_info",             //	获取JS Buffer底层data及其长度。

            // NAPI_EXTERN napi_status napi_is_buffer(napi_env env,
            //                                       napi_value value,
            //                                       bool* result);
            "napi_is_buffer"                   //	判断给定JS value是否为Buffer对象。

            ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {

        // TODO: 需要为heap空间建模

        NAPIValue callNV = recordCall(context, calleeFunc); // 记录调用的nv
        // 处理返回值
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        KSet retKset = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_STATUS, calleeFunc.getEntryPoint(), callNV, retALoc.getLen()* 8, calleeFunc, context, inOutEnv);
        inOutEnv.set(retALoc, retKset, true);

        String funcName = calleeFunc.getName();
        if(funcName.equals("napi_create_buffer")){
            // 向result中插入一个抽象值
            List<ALoc> alocs = getParamALocs(calleeFunc, 3, inOutEnv);
            // 记录这个返回值
            NAPIValue localNV = recordLocal(context, calleeFunc,3);
            // 向分析中写入一个抽象值
            KSet kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize* 8, calleeFunc, context, inOutEnv);
            for (ALoc loc: alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, kSetForValue, true); // *ptr = env
                }
            }

            // 向data分配内存 TODO 但是其实没有写入操作，只是绑定了buffer和这片内存？





        }else if(funcName.equals("napi_create_buffer_copy")) {
            // 向result中插入一个抽象值
            List<ALoc> alocs = getParamALocs(calleeFunc, 4, inOutEnv);
            // 记录这个返回值
            NAPIValue localNV = recordLocal(context, calleeFunc, 4);
            // 向分析中写入一个抽象值
            KSet kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
            for (ALoc loc : alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, kSetForValue, true); // *ptr = env
                }
            }

            // 向data分配内存

        }else if(funcName.equals("napi_create_external_buffer")) {
            // 向result中插入一个抽象值
            List<ALoc> alocs = getParamALocs(calleeFunc, 5, inOutEnv);
            // 记录这个返回值
            NAPIValue localNV = recordLocal(context, calleeFunc, 5);
            // 向分析中写入一个抽象值
            KSet kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
            for (ALoc loc : alocs) {
                KSet ks = inOutEnv.get(loc);
                for (AbsVal val : ks) {
                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                    inOutEnv.set(ptr, kSetForValue, true); // *ptr = env
                }
            }
        }else if(funcName.equals("napi_get_buffer_info")) {
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
        }else if(funcName.equals("napi_is_buffer")) {
            // 向result中插入一个抽象值
            List<ALoc> alocs = getParamALocs(calleeFunc, 2, inOutEnv);
            // 记录这个返回值
            NAPIValue localNV = recordLocal(context, calleeFunc, 2);
            // 向分析中写入一个抽象值
            KSet kSetForValue = NAPIValueManager.getKSetForValue(TypeCategory.NUMBER, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize * 8, calleeFunc, context, inOutEnv);
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
