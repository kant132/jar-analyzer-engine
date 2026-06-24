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

        // 推断 groupId：method_table 中所有 class_name 的最长公共包前缀
        List<String> allClassNames = mapper.getAllClassNames();
        String groupId = inferGroupId(allClassNames);
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

            // CTE 递归查询 (只遍历 groupId 内调用, 库调用只记为 sink)
            List<Map<String, Object>> chainNodes = mapper.extractChain(
                    String.valueOf(methodId), MAX_DEPTH, groupId + "%");
            if (chainNodes == null || chainNodes.isEmpty()) {
                continue;
            }

            totalEndpoints++;
            String endpointFqn = className.replace("/", ".") + "#" + methodName;

            // 按路径变体分组：CTE 返回所有可达节点（含 path 字段）
            // 每条唯一的 path = 一条链变体
            // 按 path 字段提取根→叶路径，每条路径生成一条 chain
            Map<String, List<Map<String, Object>>> pathVariants = new LinkedHashMap<>();
            for (Map<String, Object> node : chainNodes) {
                String path = (String) node.get("path");
                if (path == null) continue;
                pathVariants.computeIfAbsent(path, k -> new ArrayList<>()).add(node);
            }

            // 对每条路径变体生成一条 chain
            for (Map.Entry<String, List<Map<String, Object>>> variant : pathVariants.entrySet()) {
                List<Map<String, Object>> variantNodes = variant.getValue();

                // 构建-chain_path 和 node_path
                List<String> chainPathParts = new ArrayList<>();
                List<String> nodePathParts = new ArrayList<>();
                int totalSinks = 0;
                int lastSinks = 0;

                for (Map<String, Object> node : variantNodes) {
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
                params.put("nodeCount", variantNodes.size());

                mapper.insertChain(params);
                totalChains++;
            }
        }

        logger.info("chain generation complete: {} chains, {} endpoints", totalChains, totalEndpoints);
    }

    /**
     * 从所有 class_name 中找最长公共包前缀作为 groupId。
     * 例如所有类都是 com/macro/mall/... 开头 → groupId = com/macro/mall
     */
    private static String inferGroupId(List<String> classNames) {
        if (classNames == null || classNames.isEmpty()) {
            return "";
        }
        // 取所有 class_name 按 "/" 分割，找公共前缀
        List<String[]> allParts = new ArrayList<>();
        for (String cn : classNames) {
            if (cn != null && !cn.isEmpty()) {
                allParts.add(cn.split("/"));
            }
        }
        if (allParts.isEmpty()) {
            return "";
        }
        // 找所有路径的最长公共前缀
        int minLen = Integer.MAX_VALUE;
        for (String[] parts : allParts) {
            minLen = Math.min(minLen, parts.length);
        }
        // 至少要有 2 段公共前缀才算 groupId
        int commonEnd = 0;
        for (int i = 0; i < minLen; i++) {
            String seg = allParts.get(0)[i];
            boolean allMatch = true;
            for (String[] parts : allParts) {
                if (!parts[i].equals(seg)) {
                    allMatch = false;
                    break;
                }
            }
            if (allMatch) {
                commonEnd = i + 1;
            } else {
                break;
            }
        }
        // 公共前缀至少 2 段，最多取到倒数第 2 段（留至少 1 段给子包/类名）
        commonEnd = Math.min(commonEnd, minLen - 1);
        if (commonEnd < 2) {
            // 公共前缀太短，退化取第一个 class_name 的前 3 段
            String[] first = allParts.get(0);
            commonEnd = Math.min(3, first.length - 1);
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < commonEnd; i++) {
            if (i > 0) sb.append("/");
            sb.append(allParts.get(0)[i]);
        }
        return sb.toString();
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
