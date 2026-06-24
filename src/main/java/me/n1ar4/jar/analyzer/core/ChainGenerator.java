package me.n1ar4.jar.analyzer.core;

import me.n1ar4.jar.analyzer.core.mapper.ChainMapper;
import me.n1ar4.jar.analyzer.engine.log.LogManager;
import me.n1ar4.jar.analyzer.engine.log.Logger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * 在 jar-analyzer-engine 中生成调用链。
 *
 * 对 route_table 中的每个路由：
 * 1. 解析 method_id
 * 2. CTE 递归查询 method_call_table 获取所有可达方法
 * 3. 识别 sinks（非 groupId 调用）
 * 4. 写入 chains 表
 */
public class ChainGenerator {
    private static final Logger logger = LogManager.getLogger();
    private static final int MAX_DEPTH = 20;

    public static void generate() {
        ChainMapper mapper = DatabaseManager.getChainMapper();
        if (mapper == null) {
            logger.error("chain mapper not initialized");
            return;
        }

        // 清空旧链
        mapper.clearChains();
        logger.info("chains table cleared");

        // 获取所有路由
        List<Map<String, Object>> routes = mapper.getAllRoutes();
        if (routes == null || routes.isEmpty()) {
            logger.info("no routes found, skip chain generation");
            return;
        }
        logger.info("generating chains for {} routes", routes.size());

        // 推断 groupId
        String groupId = inferGroupId(routes);
        logger.info("inferred groupId: {}", groupId);

        int totalChains = 0;
        int totalEndpoints = 0;

        for (Map<String, Object> route : routes) {
            String className = (String) route.get("class_name");
            String methodName = (String) route.get("method_name");
            if (className == null || methodName == null) {
                continue;
            }

            // 解析 method_id
            Integer methodId = mapper.resolveMethodId(className, methodName);
            if (methodId == null) {
                continue;
            }

            // CTE 递归查询
            List<Map<String, Object>> chainNodes = mapper.extractChain(
                    String.valueOf(methodId), MAX_DEPTH);
            if (chainNodes == null || chainNodes.isEmpty()) {
                continue;
            }

            // 构建调用链
            totalEndpoints++;
            String endpointFqn = className.replace("/", ".") + "#" + methodName;

            // 构建 chain_path 和 node_path
            List<String> chainPathParts = new ArrayList<>();
            List<String> nodePathParts = new ArrayList<>();
            int totalSinks = 0;
            int lastSinks = 0;

            for (Map<String, Object> node : chainNodes) {
                String nodeClassName = (String) node.get("class_name");
                String nodeMethodName = (String) node.get("method_name");
                String nodeMethodDesc = (String) node.get("method_desc");
                String nodeId = String.valueOf(node.get("method_id"));

                // 识别该方法的 sinks (非 groupId 调用)
                List<Map<String, Object>> callees = mapper.getCallees(
                        nodeClassName, nodeMethodName, nodeMethodDesc);
                int sinkCount = 0;
                if (callees != null) {
                    for (Map<String, Object> callee : callees) {
                        String calleeClass = (String) callee.get("callee_class_name");
                        if (calleeClass != null && !calleeClass.startsWith(groupId)) {
                            sinkCount++;
                        }
                    }
                }

                totalSinks += sinkCount;
                lastSinks = sinkCount;

                String fqn = nodeClassName.replace("/", ".") + "#" + nodeMethodName;
                chainPathParts.add(fqn + "(sink num: " + sinkCount + ")");
                nodePathParts.add(nodeId);
            }

            // 检测环
            Set<String> seen = new HashSet<>();
            boolean cycle = false;
            for (String nid : nodePathParts) {
                if (seen.contains(nid)) {
                    cycle = true;
                    break;
                }
                seen.add(nid);
            }

            // 计算优先级
            int priority = Math.max(0, lastSinks * 10 + lastSinks);

            // 生成 chain_id (sha256 of node_path)
            String nodePathStr = String.join(" -> ", nodePathParts);
            String chainId = sha256Short(nodePathStr);

            // 构建 chain_path
            String chainPathStr = String.join(" -> ", chainPathParts);

            // 插入 chains 表
            Map<String, Object> params = new HashMap<>();
            params.put("chainId", chainId);
            params.put("endpointFqn", endpointFqn);
            params.put("priority", priority);
            params.put("totalSinks", totalSinks);
            params.put("cycleDetected", cycle ? 1 : 0);
            params.put("chainPath", chainPathStr);
            params.put("nodePath", nodePathStr);
            params.put("createdAt", new Date().toString());
            params.put("lastSinks", lastSinks);
            params.put("isSink", lastSinks > 0 ? 1 : 0);
            params.put("nodeCount", chainNodes.size());

            mapper.insertChain(params);
            totalChains++;
        }

        logger.info("chain generation complete: {} chains, {} endpoints", totalChains, totalEndpoints);
    }

    /**
     * 从 route_table 的 class_name 推断 groupId。
     * 例如: com/macro/mall/controller/OssController → com/macro/mall
     */
    private static String inferGroupId(List<Map<String, Object>> routes) {
        for (Map<String, Object> route : routes) {
            String className = (String) route.get("class_name");
            if (className == null) continue;
            String[] parts = className.split("/");
            for (int i = 0; i < parts.length; i++) {
                if ("controller".equalsIgnoreCase(parts[i]) && i > 0) {
                    return String.join("/", Arrays.copyOf(parts, i));
                }
            }
            // 如果没有 "controller"，取前3段
            if (parts.length >= 3) {
                return parts[0] + "/" + parts[1] + "/" + parts[2];
            }
        }
        return "";
    }

    private static String sha256Short(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8 && i < hash.length; i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return Integer.toHexString(input.hashCode());
        }
    }
}
