package hust.cse.ohnapisummary.env.funcs;

import com.bai.env.*;
import com.bai.env.region.RegionBase;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.caucho.hessian4.io.LocaleHandle;
import ghidra.pcodeCPort.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;
import hust.cse.ohnapisummary.util.NAPIValueManager;
import hust.cse.ohnapisummary.util.TypeCategory;

import java.util.List;
import java.util.Set;

public class NapiGetCallBackInfo extends NAPIFunctionBase{
    public NapiGetCallBackInfo() {
        super(Set.of(
                "napi_get_cb_info"
//                "napi_get_value_double",
//                "napi_create_double"

        ));
    }

//    // Gets all callback info in a single call. (Ugly, but faster.)
//    napi_status napi_get_cb_info(
//            napi_env env,               // [in] NAPI environment handle
//            napi_callback_info cbinfo,  // [in] Opaque callback-info handle
//            size_t* argc,               // [in-out] Specifies the size of the provided argv array
//            // and receives the actual count of args.
//            napi_value* argv,           // [out] Array of values
//            napi_value* this_arg,       // [out] Receives the JS 'this' arg for the call
//            void** data);               // [out] Receives the data pointer for the callback.


    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
        NAPIValue callNV = recordCall(context, calleeFunc); // 记录调用的nv

        String funcName = calleeFunc.getName();
        // 获取argc 传入的值
        List<ALoc> alocs = getParamALocs(calleeFunc, 2, inOutEnv);
        long size = 0;
        for (ALoc loc: alocs) {
            KSet ks = inOutEnv.get(loc);
            for (AbsVal val : ks) {

                ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                KSet Num = inOutEnv.get(ptr);
                Logging.info(funcName + " argc is a local value AbsVal:" + Num );
                for (AbsVal numAbsVal : Num) {
                    // 判断是 global 即常量，然后取出来到Size，保证只取出一个数组，如果 取出不同数字就报错，不继续后面的
                    if(numAbsVal.getRegion().isGlobal()){
                        size = numAbsVal.getValue();
                    }else{
                        Logging.error("Can't get the size of argc in napi_get_cb_info call");
                    }
                }

            }
        }
//        // 获取p3传入值指向的地址
//        Address address = null;
        alocs = getParamALocs(calleeFunc, 3, inOutEnv);
        ALoc starPtrAloc = null;
        for (ALoc loc: alocs) {
            KSet ks = inOutEnv.get(loc);
            for (AbsVal val : ks) {
                // 获取传入的地址
                starPtrAloc = toALoc(val, MyGlobalState.defaultPointerSize); //这一步相当于取地址
                Logging.info(funcName + " starPtr is a local value AbsVal:" + starPtrAloc );
                // 保证只有一个地址？多个可能也可以都赋值？
            }
        }
        long starPtr = starPtrAloc.getBegin();
        // 获取对应位置的Aloc
        RegionBase region = starPtrAloc.getRegion();
        Logging.info(funcName + " starPtr is a local value Region:" + region );

        for(int i=0; i<size;i++) {
            // 往上面的指针里面放有污点的值
            // TODO:改为正确的
            NAPIValue localNV = recordLocalMultiRet(context, calleeFunc, 3, i);
            KSet env = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_VALUE, calleeFunc.getEntryPoint(), localNV, MyGlobalState.defaultPointerSize* 8, calleeFunc, context, inOutEnv);
            assert env.getInnerSet().size() == 1;
            inOutEnv.set(starPtrAloc, env, true);

            // 获取下一个地址处的Aloc
            starPtr += MyGlobalState.defaultPointerSize;
            starPtrAloc = ALoc.getALoc(region, starPtr, MyGlobalState.defaultPointerSize);
            // TODO 有没有可能越界
        }


        // TODO
        // 向p4传入值

        // 向p5传入值


        // 处理返回值
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        KSet retKset = NAPIValueManager.getKSetForValue(TypeCategory.NAPI_STATUS, calleeFunc.getEntryPoint(), callNV, retALoc.getLen()* 8, calleeFunc, context, inOutEnv);
        inOutEnv.set(retALoc, retKset, true);


    }
}
