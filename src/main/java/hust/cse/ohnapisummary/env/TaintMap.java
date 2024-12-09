package hust.cse.ohnapisummary.env;

import com.bai.util.Logging;
import hust.cse.ohnapisummary.util.NAPIValue;

import java.util.HashMap;
import java.util.Map;

public class TaintMap {
    private static int taintId = 0;
    private static final int MAX_TAINT_CNT = 64;
    private static final Map<NAPIValue, Integer> taintSourceToIdMap = new HashMap<>();

    /**
     * Reset the maintained relationship
     */
    public static void reset() {
        taintId = 0;
        taintSourceToIdMap.clear();
    }

    protected static int getTaintId(NAPIValue napiValue) {
        if (taintId >= MAX_TAINT_CNT) {
            Logging.error("Taint id number reach " + MAX_TAINT_CNT
                    + "this may lead to false positive.");
            taintId = taintId % MAX_TAINT_CNT;
            return 0; //
        }
        Integer id = taintSourceToIdMap.get(napiValue);
        if (id != null) {
            return id;
        }
        taintSourceToIdMap.put(napiValue, taintId);
        id = taintId;
        taintId++;
        return id;
    }

    public static long getTaints(NAPIValue napiValue) {
        return 1L << getTaintId(napiValue);
    }

    public static boolean isNewTaint(long taint) {
        if (taintId == 0) return false;
        if (taint == (1L << (taintId-1))) {
            return true;
        }
        return false;
    }

    /**
     * Get a taint bitmap for a taint source with a specific taint id
     * @param taintId Taint id for an existing taint source
     * @return Taint bitmap for the given taint id
     */
    public static long getTaints(int taintId) {
        return 1L << taintId;
    }

}
