/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.engine;

import me.n1ar4.jar.analyzer.analyze.jaxrs.JaxRsMapping;
import me.n1ar4.jar.analyzer.analyze.jaxrs.JaxRsResource;
import me.n1ar4.jar.analyzer.analyze.jaxrs.JaxRsService;
import me.n1ar4.jar.analyzer.analyze.jaxws.JaxWsEndpoint;
import me.n1ar4.jar.analyzer.analyze.jaxws.JaxWsOperation;
import me.n1ar4.jar.analyzer.analyze.jaxws.JaxWsService;
import me.n1ar4.jar.analyzer.analyze.spring.SpringController;
import me.n1ar4.jar.analyzer.analyze.spring.SpringMapping;
import me.n1ar4.jar.analyzer.analyze.spring.SpringService;
import me.n1ar4.jar.analyzer.core.*;
import me.n1ar4.jar.analyzer.core.asm.FixClassVisitor;
import me.n1ar4.jar.analyzer.core.asm.StringClassVisitor;
import me.n1ar4.jar.analyzer.core.reference.AnnoReference;
import me.n1ar4.jar.analyzer.core.reference.ClassReference;
import me.n1ar4.jar.analyzer.core.reference.MethodReference;
import me.n1ar4.jar.analyzer.engine.log.LogManager;
import me.n1ar4.jar.analyzer.engine.log.Logger;
import me.n1ar4.jar.analyzer.engine.utils.*;
import me.n1ar4.jar.analyzer.entity.ClassFileEntity;
import me.n1ar4.jar.analyzer.entity.JarEntity;
import me.n1ar4.jar.analyzer.entity.RouteEntry;
import org.objectweb.asm.ClassReader;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Engine Build Runner - core analysis pipeline without any GUI dependency.
 * Extracted from CoreRunner, driven by EngineConfig.
 */
public class EngineBuildRunner {
    private static final Logger logger = LogManager.getLogger();

    public static void run(EngineConfig config) {
        ProgressCallback callback = config.getProgressCallback();
        if (callback == null) {
            callback = ProgressCallback.CONSOLE;
        }

        // Clear all state for re-entrant safety
        AnalyzeEnv.classFileList.clear();
        AnalyzeEnv.discoveredClasses.clear();
        AnalyzeEnv.discoveredMethods.clear();
        AnalyzeEnv.methodsInClassMap.clear();
        AnalyzeEnv.classMap.clear();
        AnalyzeEnv.methodMap.clear();
        AnalyzeEnv.methodCalls.clear();
        AnalyzeEnv.strMap.clear();
        AnalyzeEnv.controllers.clear();
        AnalyzeEnv.jaxRsResources.clear();
        AnalyzeEnv.jaxWsEndpoints.clear();
        AnalyzeEnv.interceptors.clear();
        AnalyzeEnv.servlets.clear();
        AnalyzeEnv.filters.clear();
        AnalyzeEnv.listeners.clear();
        AnalyzeEnv.stringAnnoMap.clear();
        AnalyzeEnv.corruptedFiles.clear();

        // Setup JarUtil with black/white list
        JarUtil.setBlackListText(config.getClassBlackList());
        JarUtil.setWhiteListText(config.getClassWhiteList());
        JarUtil.setInputFileText(config.getJarPath().toAbsolutePath().toString());

        // Setup AnalyzeEnv
        AnalyzeEnv.jarsInJar = config.isJarsInJar();

        Path jarPath = config.getJarPath();
        Path rtJarPath = config.getRtJarPath();
        boolean fixClass = config.isFixClass();
        boolean quickMode = config.isQuickMode();

        Map<String, Integer> jarIdMap = new HashMap<>();
        List<ClassFileEntity> cfs;

        callback.onProgress(10);

        if (Files.isDirectory(jarPath)) {
            logger.info("input is a dir");
            callback.onInfo("input is a dir");
            List<String> files = DirUtil.GetFiles(jarPath.toAbsolutePath().toString());
            if (rtJarPath != null) {
                files.add(rtJarPath.toAbsolutePath().toString());
                callback.onInfo("analyze with rt.jar file");
            }
            callback.onStats("totalJar", String.valueOf(files.size()));
            for (String s : files) {
                if (s.toLowerCase().endsWith(".jar") ||
                        s.toLowerCase().endsWith(".war")) {
                    DatabaseManager.saveJar(s);
                    JarEntity jarEntity = DatabaseManager.getJarId(s);
                    if (jarEntity != null) {
                        jarIdMap.put(s, jarEntity.getJid());
                    } else {
                        logger.error("save jar failed, cannot get jar id: {}", s);
                    }
                }
            }
            cfs = CoreUtil.getAllClassesFromJars(files, jarIdMap);
        } else {
            logger.info("input is a jar file");
            callback.onInfo("input is a jar");
            List<String> jarList = new ArrayList<>();
            if (rtJarPath != null) {
                jarList.add(rtJarPath.toAbsolutePath().toString());
                callback.onInfo("analyze with rt.jar file");
            }
            jarList.add(jarPath.toAbsolutePath().toString());
            callback.onStats("totalJar", String.valueOf(jarList.size()));
            for (String s : jarList) {
                DatabaseManager.saveJar(s);
                JarEntity jarEntity = DatabaseManager.getJarId(s);
                if (jarEntity != null) {
                    jarIdMap.put(s, jarEntity.getJid());
                } else {
                    logger.error("save jar failed, cannot get jar id: {}", s);
                }
            }
            cfs = CoreUtil.getAllClassesFromJars(jarList, jarIdMap);
        }

        // Fix class names
        for (ClassFileEntity cf : cfs) {
            String className = cf.getClassName();
            if (!fixClass) {
                if (className.contains("BOOT-INF") || className.contains("WEB-INF")) {
                    int i = className.indexOf("classes");
                    if (i >= 0) {
                        className = className.substring(i + 8);
                    }
                }
                cf.setClassName(className);
            } else {
                Path parPath = Paths.get(EngineConst.tempDir);
                FixClassVisitor cv = new FixClassVisitor();
                byte[] fileBytes = cf.getFile();
                if (fileBytes == null) {
                    logger.error("cannot read class file: {}", cf.getClassName());
                    continue;
                }
                try {
                    ClassReader cr = new ClassReader(fileBytes);
                    cr.accept(cv, EngineConst.AnalyzeASMOptions);
                } catch (IndexOutOfBoundsException e) {
                    if (!StackMapFrameHandler.handleParseException(fileBytes, cv,
                            cf.getJarName() + "!" + cf.getClassName(),
                            logger, "fix class name", e)) {
                        throw e;
                    }
                }
                Path path = parPath.resolve(Paths.get(cv.getName()));
                File file = path.toFile();
                if (!file.getParentFile().exists() && !file.getParentFile().mkdirs()) {
                    logger.error("fix class mkdirs error");
                }
                className = file.getPath() + ".class";
                try (ByteArrayInputStream bis = new ByteArrayInputStream(fileBytes);
                     FileOutputStream fos = new FileOutputStream(className)) {
                    IOUtil.copy(bis, fos);
                } catch (IOException ex) {
                    logger.error("fix path copy bytes error: {}", ex.toString());
                }
                cf.setClassName(className);
                cf.setPath(Paths.get(className));
            }
        }

        callback.onProgress(15);
        AnalyzeEnv.classFileList.addAll(cfs);
        logger.info("get all class");
        callback.onInfo("get all class");
        DatabaseManager.saveClassFiles(AnalyzeEnv.classFileList);

        callback.onProgress(20);
        DiscoveryRunner.start(AnalyzeEnv.classFileList, AnalyzeEnv.discoveredClasses,
                AnalyzeEnv.discoveredMethods, AnalyzeEnv.classMap,
                AnalyzeEnv.methodMap, AnalyzeEnv.stringAnnoMap);
        DatabaseManager.saveClassInfo(AnalyzeEnv.discoveredClasses);

        callback.onProgress(25);
        DatabaseManager.saveMethods(AnalyzeEnv.discoveredMethods);

        callback.onProgress(30);
        logger.info("analyze class finish");
        callback.onInfo("analyze class finish");
        callback.onStats("totalClass", String.valueOf(DatabaseManager.getTotalClassCount()));
        callback.onStats("totalMethod", String.valueOf(DatabaseManager.getTotalMethodCount()));

        for (MethodReference mr : AnalyzeEnv.discoveredMethods) {
            ClassReference.Handle ch = mr.getClassReference();
            if (AnalyzeEnv.methodsInClassMap.get(ch) == null) {
                List<MethodReference> ml = new ArrayList<>();
                ml.add(mr);
                AnalyzeEnv.methodsInClassMap.put(ch, ml);
            } else {
                List<MethodReference> ml = AnalyzeEnv.methodsInClassMap.get(ch);
                ml.add(mr);
                AnalyzeEnv.methodsInClassMap.put(ch, ml);
            }
        }

        callback.onProgress(35);
        MethodCallRunner.start(AnalyzeEnv.classFileList, AnalyzeEnv.methodCalls);
        callback.onProgress(40);

        if (!quickMode) {
            AnalyzeEnv.inheritanceMap = InheritanceRunner.derive(AnalyzeEnv.classMap);
            callback.onProgress(50);
            logger.info("build inheritance");
            callback.onInfo("build inheritance");

            Map<MethodReference.Handle, Set<MethodReference.Handle>> implMap =
                    InheritanceRunner.getAllMethodImplementations(
                            AnalyzeEnv.inheritanceMap, AnalyzeEnv.methodMap);
            DatabaseManager.saveImpls(implMap);
            callback.onProgress(60);

            if (config.isFixMethodImpl()) {
                for (Map.Entry<MethodReference.Handle, Set<MethodReference.Handle>> entry :
                        implMap.entrySet()) {
                    MethodReference.Handle k = entry.getKey();
                    Set<MethodReference.Handle> v = entry.getValue();
                    HashSet<MethodReference.Handle> calls = AnalyzeEnv.methodCalls.get(k);
                    if (calls != null) {
                        calls.addAll(v);
                    }
                }
            } else {
                logger.warn("enable fix method impl/override is recommend");
            }

            DatabaseManager.saveMethodCalls(AnalyzeEnv.methodCalls);
            callback.onProgress(70);
            logger.info("build extra inheritance");
            callback.onInfo("build extra inheritance");

            for (ClassFileEntity file : AnalyzeEnv.classFileList) {
                try {
                    byte[] fileBytes = file.getFile();
                    if (fileBytes == null) {
                        logger.error("cannot read class file for string analysis: {}", file.getClassName());
                        continue;
                    }
                    StringClassVisitor dcv = new StringClassVisitor(
                            AnalyzeEnv.strMap, AnalyzeEnv.classMap, AnalyzeEnv.methodMap);
                    ClassReader cr = new ClassReader(fileBytes);
                    cr.accept(dcv, EngineConst.AnalyzeASMOptions);
                } catch (IndexOutOfBoundsException e) {
                    if (!StackMapFrameHandler.handleParseException(file,
                            new StringClassVisitor(AnalyzeEnv.strMap,
                                    AnalyzeEnv.classMap, AnalyzeEnv.methodMap),
                            logger, "string analysis", e)) {
                        logger.error("string analyze error: {}", e.toString());
                    }
                } catch (Exception ex) {
                    logger.error("string analyze error: {}", ex.toString());
                }
            }

            callback.onProgress(80);
            DatabaseManager.saveStrMap(AnalyzeEnv.strMap, AnalyzeEnv.stringAnnoMap);

            SpringService.start(AnalyzeEnv.classFileList, AnalyzeEnv.controllers,
                    AnalyzeEnv.classMap, AnalyzeEnv.methodMap);
            DatabaseManager.saveSpringController(AnalyzeEnv.controllers);

            // 把 Spring MVC 路由也写入统一的 route_table
            List<RouteEntry> springRoutes = new ArrayList<>();
            for (SpringController controller : AnalyzeEnv.controllers) {
                for (SpringMapping mapping : controller.getMappings()) {
                    RouteEntry entry = new RouteEntry();
                    entry.setClassName(controller.getClassName().getName());
                    entry.setMethodName(mapping.getMethodName().getName());
                    entry.setMethodDesc(mapping.getMethodName().getDesc());
                    entry.setFramework("spring-mvc");
                    String path = mapping.getPath();
                    if (path == null || path.isEmpty()) {
                        path = "none";
                    }
                    entry.setPath(path);
                    entry.setBasePath(controller.getBasePath());
                    String restful = mapping.getPathRestful();
                    if (restful != null && !restful.isEmpty()) {
                        entry.setHttpMethod(restful);
                    } else {
                        if (mapping.getMethodReference() != null) {
                            for (AnnoReference anno : mapping.getMethodReference().getAnnotations()) {
                                String annoName = anno.getAnnoName();
                                if (annoName == null) {
                                    continue;
                                }
                                if (annoName.contains("GetMapping")) {
                                    entry.setHttpMethod("GET");
                                    break;
                                } else if (annoName.contains("PostMapping")) {
                                    entry.setHttpMethod("POST");
                                    break;
                                } else if (annoName.contains("PutMapping")) {
                                    entry.setHttpMethod("PUT");
                                    break;
                                } else if (annoName.contains("DeleteMapping")) {
                                    entry.setHttpMethod("DELETE");
                                    break;
                                } else if (annoName.contains("PatchMapping")) {
                                    entry.setHttpMethod("PATCH");
                                    break;
                                } else if (annoName.contains("RequestMapping")) {
                                    entry.setHttpMethod("REQUEST");
                                    break;
                                }
                            }
                        }
                    }
                    entry.setJarId(controller.getClassReference().getJarId());
                    springRoutes.add(entry);
                }
            }
            DatabaseManager.saveRoutes(springRoutes);

            // JAX-RS route discovery
            JaxRsService.start(AnalyzeEnv.classFileList, AnalyzeEnv.jaxRsResources,
                    AnalyzeEnv.classMap, AnalyzeEnv.methodMap);

            // JAX-WS route discovery
            JaxWsService.start(AnalyzeEnv.classFileList, AnalyzeEnv.jaxWsEndpoints,
                    AnalyzeEnv.classMap, AnalyzeEnv.methodMap);

            // Build unified route_table entries
            List<RouteEntry> allRoutes = new ArrayList<>();
            for (JaxRsResource res : AnalyzeEnv.jaxRsResources) {
                for (JaxRsMapping m : res.getMappings()) {
                    RouteEntry entry = new RouteEntry();
                    entry.setClassName(res.getClassName().getName());
                    entry.setMethodName(m.getMethodName().getName());
                    entry.setMethodDesc(m.getMethodName().getDesc());
                    entry.setFramework("jax-rs");
                    entry.setHttpMethod(m.getHttpMethod());
                    entry.setPath(m.getPath());
                    entry.setBasePath(res.getBasePath());
                    entry.setMethodPath(m.getMethodPath());
                    entry.setJarId(res.getClassReference().getJarId());
                    allRoutes.add(entry);
                }
            }
            for (JaxWsEndpoint ep : AnalyzeEnv.jaxWsEndpoints) {
                for (JaxWsOperation op : ep.getOperations()) {
                    if (op.isExclude()) {
                        continue;
                    }
                    RouteEntry entry = new RouteEntry();
                    entry.setClassName(ep.getClassName().getName());
                    entry.setMethodName(op.getMethodName().getName());
                    entry.setMethodDesc(op.getMethodName().getDesc());
                    entry.setFramework("jax-ws");
                    entry.setHttpMethod("POST");
                    String serviceName = ep.getServiceName();
                    if (serviceName == null || serviceName.isEmpty()) {
                        serviceName = ep.getClassName().getName().replace("/", ".");
                        serviceName = serviceName.substring(serviceName.lastIndexOf(".") + 1);
                    }
                    entry.setPath("/services/" + serviceName);
                    entry.setBasePath("/services/" + serviceName);
                    entry.setJarId(ep.getClassReference().getJarId());
                    allRoutes.add(entry);
                }
            }
            DatabaseManager.saveRoutes(allRoutes);

            OtherWebService.start(AnalyzeEnv.classFileList,
                    AnalyzeEnv.interceptors,
                    AnalyzeEnv.servlets, AnalyzeEnv.filters, AnalyzeEnv.listeners);
            DatabaseManager.saveSpringInterceptor(AnalyzeEnv.interceptors);
            DatabaseManager.saveServlets(AnalyzeEnv.servlets);
            DatabaseManager.saveFilters(AnalyzeEnv.filters);
            DatabaseManager.saveListeners(AnalyzeEnv.listeners);

            callback.onProgress(90);
        } else {
            callback.onProgress(70);
            DatabaseManager.saveMethodCalls(AnalyzeEnv.methodCalls);
        }

        logger.info("build database finish");
        callback.onInfo("build database finish");

        long fileSizeBytes = new File(EngineConst.dbFile).length();
        String fileSizeMB = String.format("%.2f MB", (double) fileSizeBytes / (1024 * 1024));
        callback.onStats("dbSize", fileSizeMB);

        callback.onProgress(100);

        // Report corrupted files
        if (!AnalyzeEnv.corruptedFiles.isEmpty()) {
            callback.onWarn("corrupted files count: " + AnalyzeEnv.corruptedFiles.size());
            for (String fileInfo : AnalyzeEnv.corruptedFiles) {
                callback.onWarn("corrupted: " + fileInfo);
            }
        }

        // GC
        AnalyzeEnv.classFileList.clear();
        AnalyzeEnv.discoveredClasses.clear();
        AnalyzeEnv.discoveredMethods.clear();
        AnalyzeEnv.methodsInClassMap.clear();
        AnalyzeEnv.classMap.clear();
        AnalyzeEnv.methodMap.clear();
        AnalyzeEnv.methodCalls.clear();
        AnalyzeEnv.strMap.clear();
        AnalyzeEnv.stringAnnoMap.clear();
        AnalyzeEnv.interceptors.clear();
        AnalyzeEnv.servlets.clear();
        AnalyzeEnv.filters.clear();
        AnalyzeEnv.listeners.clear();
        AnalyzeEnv.corruptedFiles.clear();
        if (!quickMode) {
            if (AnalyzeEnv.inheritanceMap != null) {
                AnalyzeEnv.inheritanceMap.getInheritanceMap().clear();
                AnalyzeEnv.inheritanceMap.getSubClassMap().clear();
            }
        }
        AnalyzeEnv.controllers.clear();
        AnalyzeEnv.jaxRsResources.clear();
        AnalyzeEnv.jaxWsEndpoints.clear();
        System.gc();
    }
}
