package hust.cse.ohnapisummary.env.funcs;

import com.bai.env.*;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.region.Heap;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.env.MyTaintMap;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;
import hust.cse.ohnapisummary.util.NAPIValueManager;
import hust.cse.ohnapisummary.util.TypeCategory;

import java.util.List;
import java.util.Set;

public abstract class NAPIFunctionBase extends ExternalFunctionBase {

    public static Address currentCallSite;

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

    public static NAPIValue recordAllocCall(Context context, Function callFunc, Heap heap) {
        NAPIValue jcs = recordCall(context, callFunc);
        MyGlobalState.napiManager.heapMap.put(heap, jcs);
        return jcs;
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
//        String funcName = calleeFunc.getName();
//        KSet ret = null;
//        ALoc retALoc = getReturnALoc(calleeFunc, false);
//
//
//        if (funcName.equals("napi_define_properties")) {
//            // 记录动态注册信息
//            NAPIValue nv = recordCall(context, calleeFunc);
//        } else if (funcName.equals("napi_module_register")) {
//            // 记录动态注册信息
//            NAPIValue nv = recordCall(context, calleeFunc);
//        }else if(funcName.equals("napi_set_named_property")){
//            // 记录动态注册信息
//            NAPIValue nv = recordCall(context, calleeFunc);
//        }else if(funcName.equals("napi_create_function")){
//            // 记录动态注册信息
//            NAPIValue nv = recordCall(context, calleeFunc);
//        }else if (funcName.equals("napi_get_cb_info")) {
//            NAPIValue nv = recordCall(context, calleeFunc);
//            // 获取argc
////            List<ALoc> alocs = getParamALocs(calleeFunc, index, inOutEnv);
//            // 创建抽象值 Kset,存入一个带污点的值
//
//            // 放到抽象内存里
////            inOutEnv.set(ptr, env, true);
//
//            // 获取argc
//            // napi_get_cb_info(env, info, &argc, args , nullptr, nullptr);
//            List<ALoc> alocs = getParamALocs(calleeFunc, 2, inOutEnv);
//            for (ALoc loc: alocs) {
//                KSet ks = inOutEnv.get(loc);
//                for (AbsVal val: ks) {
//                    Logging.info("AbsVal: " + val);
//                    long ptr = val.getValue();
//                    Logging.info("napi_get_cb_info: argc ptr: 0x" + Long.toHexString(ptr));
//                    long pointedAddr = 0;
//                    try {
//                        pointedAddr = getValueFromAddrWithPtrSize(ptr, MyGlobalState.defaultPointerSize);
//                        Logging.info("napi_get_cb_info: argc pointedAddr: 0x" + Long.toHexString(pointedAddr));
//                    } catch (MemoryAccessException e) {
//                        Logging.error("Failed to read argc value from address: 0x" + Long.toHexString(ptr));
//                    }
//
////                    try {
////                        long size = getValueFromAddrWithPtrSize(sizePtr, MyGlobalState.defaultPointerSize);
////                        Logging.info("napi_get_cb_info: argc size: " + size);
////                    } catch (MemoryAccessException e) {
////                        Logging.error("Failed to read argc value from address: 0x" + Long.toHexString(sizePtr));
////                    }
//                }
//            }
//
//
//
//
//
//
//        } else if (funcName.equals("napi_get_value_double")) {
//            //NAPI_EXTERN napi_status napi_get_value_double(napi_env env,
//            //                                              napi_value value,
//            //                                              double* result);
//            NAPIValue nv = recordCall(context, calleeFunc); // 记录调用的nv
//            // TODO:还应该有一个记录参数的nv
//            // 向result中插入一个抽象值
//            List<ALoc> alocs = getParamALocs(calleeFunc, 2, inOutEnv);
//            Parameter param = calleeFunc.getParameter(2);
//            DataType dataType = param.getDataType();
//            for (ALoc loc: alocs) {
//                KSet ks = inOutEnv.get(loc);
//                for (AbsVal val : ks) {
//                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
//                    // TODO: 插入抽象值
//                    KSet env = NAPIValueManager.getKSetForValue(dataType, calleeFunc.getEntryPoint(), nv, MyGlobalState.defaultPointerSize*8, calleeFunc, context, inOutEnv);
//                    assert env.getInnerSet().size() == 1;
//                    inOutEnv.set(ptr, env, true);
//                }
//            }
//
//        } else if (funcName.equals("napi_create_double")) {
//            NAPIValue nv = recordCall(context, calleeFunc);
//            //napi_status napi_create_double(napi_env env,
//            //                               double value,
//            //                               napi_value* result);
//            List<ALoc> alocs = getParamALocs(calleeFunc, 2, inOutEnv);
//            for (ALoc loc: alocs) {
//                KSet ks = inOutEnv.get(loc);
//                for (AbsVal val : ks) {
//                    ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
//                    KSet env = new KSet(MyGlobalState.defaultPointerSize*8);
//                    env = env.insert(new AbsVal(0)); // TODO: 插入抽象值，应该是多少呢？？？
//                    assert env.getInnerSet().size() == 1;
//                    inOutEnv.set(ptr, env, true);
//                }
//            }
//
//
//
//        }
//
//
//        if (ret != null) {
//            inOutEnv.set(retALoc, ret, true);
//        }
    }

    private long getValueFromAddrWithPtrSize(long addr, int ptrSize) throws MemoryAccessException {
        Memory memory = GlobalState.currentProgram.getMemory();
        if (ptrSize == 4) {
            return memory.getInt(GlobalState.flatAPI.toAddr(addr));
        } else if (ptrSize == 8) {
            return memory.getLong(GlobalState.flatAPI.toAddr(addr));
        } else {
            Logging.error("Unknown ptrSize: " + ptrSize);
            return 0;
        }
    }

    public static ALoc toALoc(AbsVal val, int size) {
        return ALoc.getALoc(val.getRegion(), val.getValue(), size);
    }



}
