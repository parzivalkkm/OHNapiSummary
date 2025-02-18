package hust.cse.ohnapisummary.util;

import com.bai.env.ALoc;
import com.bai.env.Context;
import com.bai.util.GlobalState;
import ghidra.program.model.listing.Function;

import java.util.Arrays;
import java.util.Objects;

public class NAPIValue {


    enum NAPIValueCategory {
        PARAM,
        LOCAL,
        FUNC_CALL
    };
    NAPIValueCategory napiValueCategory;

    public boolean isParamValue() {
        return napiValueCategory == NAPIValueCategory.PARAM;
    }

    /*************************************************************************
     *
     *  NAPIValueCategory为FUNC_CALL时的field
     *
     *************************************************************************/

    public long callSite;

    Function api = null;
    public long[] callstring = new long[GlobalState.config.getCallStringK()];

    public NAPIValue(Context ctx, Function api, long callSite) { // NAPI调用类型的Constructor
        this.napiValueCategory = NAPIValueCategory.FUNC_CALL;
        this.api = api;
        if (ctx != null) {
            System.arraycopy(ctx.getCallString(), 0, this.callstring, 0, GlobalState.config.getCallStringK());
        }
        this.callSite = callSite;
    }

    public Function getApi() {
        if (napiValueCategory != NAPIValueCategory.FUNC_CALL) {
            throw new RuntimeException("NAPIValue is not a function call");
        }
        return api;
    }

    /*************************************************************************
     *
     *  NAPIValueCategory为PARAM时的field
     *
     *************************************************************************/

    int paramIndex = -1;   // 参数类型（PARAM）时的属性

    public NAPIValue(int index) { // 参数类型的Constructor
        this.napiValueCategory = NAPIValueCategory.PARAM;
        this.paramIndex = index;
    }

    public int getParamIndex() {
        if (napiValueCategory != NAPIValueCategory.PARAM) {
            throw new RuntimeException("NAPIValue is not a parameter");
        }
        return paramIndex;
    }

    /*************************************************************************
     *
     *  NAPIValueCategory为LOCAL时的field
     *
     *************************************************************************/

    Long localAlocBegin = 0L;
    int localAlocLen = 0;

    public NAPIValue(Function api, long callSite, ALoc aloc) { // 局部变量类型的Constructor
        this.napiValueCategory = NAPIValueCategory.LOCAL;
        this.api = api;
        this.callSite = callSite;
        this.localAlocBegin = aloc.getBegin();
        this.localAlocLen = aloc.getLen();
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NAPIValue napiValue = (NAPIValue) o;
        return paramIndex == napiValue.paramIndex && callSite == napiValue.callSite && napiValueCategory == napiValue.napiValueCategory
            && Objects.equals(api, napiValue.api) && Arrays.equals(callstring, napiValue.callstring) && localAlocBegin.equals(napiValue.localAlocBegin) && localAlocLen == napiValue.localAlocLen;
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(napiValueCategory, api, paramIndex, callSite, localAlocBegin, localAlocLen);
        result = 31 * result + Arrays.hashCode(callstring);
        return result;
    }

    public boolean isRegisterFunction() {
        return napiValueCategory == NAPIValueCategory.FUNC_CALL && api.getName().contains("napi_module_register");
    }
}
