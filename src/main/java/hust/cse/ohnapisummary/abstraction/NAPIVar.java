package hust.cse.ohnapisummary.abstraction;


import ghidra.pcodeCPort.address.Address;
import ghidra.program.model.listing.Function;
import hust.cse.ohnapisummary.util.TypeCategory;

public class NAPIVar {
    enum NAPIVarCategory {
        PARAM,
        LOCAL
    };
    NAPIVarCategory napiVarCategory;

    public boolean isParam() {
        return napiVarCategory == NAPIVarCategory.PARAM;
    }

    /*************************************************************************
     *
     *  Shred field
     *
     *  For Unique Hash
     *
     *************************************************************************/

    public long callSite = -1;

    public Function api = null;

    /*************************************************************************
     *
     *  PARAM
     *
     *************************************************************************/

    int paramIndex = -1;   // 参数类型（PARAM）时的属性

    public NAPIVar(int index) { // 参数类型的Constructor
        this.napiVarCategory = NAPIVarCategory.PARAM;
        this.paramIndex = index;
    }

    /*************************************************************************
     *
     * LOCAL
     *
     *************************************************************************/

    int localId = -1;
    Address localAddr = null;
    TypeCategory localType = TypeCategory.UNKNOWN;

    public NAPIVar(int id, TypeCategory type) { // LOCAL类型的Constructor
        this.napiVarCategory = NAPIVarCategory.LOCAL;
        this.localId = id;
        this.localType = type;
    }




    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NAPIVar napiVar = (NAPIVar) o;
        return paramIndex == napiVar.paramIndex && callSite == napiVar.callSite && napiVarCategory == napiVar.napiVarCategory
            && api.equals(napiVar.api) && localId == napiVar.localId && localType == napiVar.localType;
    }

    @Override
    public int hashCode() {
        return (int) callSite;
    }

}
