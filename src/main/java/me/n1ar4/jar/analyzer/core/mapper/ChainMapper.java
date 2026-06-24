package me.n1ar4.jar.analyzer.core.mapper;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;
import java.util.Map;

public interface ChainMapper {

    // Resolve method_id from class_name + method_name
    @Select("SELECT method_id FROM method_table WHERE class_name = #{className} AND method_name = #{methodName} LIMIT 1")
    Integer resolveMethodId(@Param("className") String className, @Param("methodName") String methodName);

    // CTE recursive query — only traverses groupId callees, library calls are sinks (not followed)
    // Two UNION ALL branches:
    //   Branch 1: direct call via method_call_table (only groupId callees)
    //   Branch 2: interface/abstract → concrete impl via method_impl_table (only groupId)
    // Dedup by class_name+method_name+method_desc (not just method_id) to prevent FQN repetition
    @Select("WITH RECURSIVE chain(method_id, class_name, method_name, method_desc, depth, path) AS (" +
            "  SELECT m.method_id, m.class_name, m.method_name, m.method_desc, 0, " +
            "         '|' || m.class_name || '|' || m.method_name || '|' || m.method_desc || '|' " +
            "  FROM method_table m WHERE CAST(m.method_id AS TEXT) = #{entryId} " +
            "  UNION " +
            "  SELECT callee.method_id, callee.class_name, callee.method_name, callee.method_desc, c.depth + 1, " +
            "         c.path || callee.class_name || '|' || callee.method_name || '|' || callee.method_desc || '|' " +
            "  FROM chain c " +
            "  JOIN method_call_table mc ON mc.caller_method_name = c.method_name " +
            "       AND mc.caller_class_name = c.class_name AND mc.caller_method_desc = c.method_desc " +
            "  JOIN method_table callee ON callee.method_name = mc.callee_method_name " +
            "       AND callee.class_name = mc.callee_class_name AND callee.method_desc = mc.callee_method_desc " +
            "  WHERE c.depth < #{maxDepth} " +
            "    AND callee.class_name LIKE #{groupIdPrefix} " +
            "    AND instr(c.path, '|' || callee.class_name || '|' || callee.method_name || '|' || callee.method_desc || '|') = 0 " +
            "  UNION " +
            "  SELECT impl.method_id, impl.class_name, impl.method_name, impl.method_desc, c.depth + 1, " +
            "         c.path || impl.class_name || '|' || impl.method_name || '|' || impl.method_desc || '|' " +
            "  FROM chain c " +
            "  JOIN method_impl_table mi ON mi.class_name = c.class_name " +
            "       AND mi.method_name = c.method_name AND mi.method_desc = c.method_desc " +
            "  JOIN method_table impl ON impl.class_name = mi.impl_class_name " +
            "       AND impl.method_name = mi.method_name AND impl.method_desc = mi.method_desc " +
            "  WHERE c.depth < #{maxDepth} " +
            "    AND impl.class_name LIKE #{groupIdPrefix} " +
            "    AND instr(c.path, '|' || impl.class_name || '|' || impl.method_name || '|' || impl.method_desc || '|') = 0 " +
            ") " +
            "SELECT method_id, class_name, method_name, method_desc, depth, path FROM chain ORDER BY depth")
    List<Map<String, Object>> extractChain(@Param("entryId") String entryId,
                                            @Param("maxDepth") int maxDepth,
                                            @Param("groupIdPrefix") String groupIdPrefix);

    // Get all callees for a method (for sink identification)
    @Select("SELECT DISTINCT callee_class_name, callee_method_name FROM method_call_table " +
            "WHERE caller_class_name = #{className} AND caller_method_name = #{methodName} AND caller_method_desc = #{methodDesc}")
    List<Map<String, Object>> getCallees(@Param("className") String className,
                                          @Param("methodName") String methodName,
                                          @Param("methodDesc") String methodDesc);

    // Insert chain
    void insertChain(Map<String, Object> params);

    // Clear all chains
    void clearChains();

    // Get all routes for chain generation
    @Select("SELECT DISTINCT class_name, method_name FROM route_table")
    List<Map<String, Object>> getAllRoutes();

    // Get groupId from jar_table (first jar name)
    @Select("SELECT jar_name FROM jar_table LIMIT 1")
    String getFirstJarName();
}
