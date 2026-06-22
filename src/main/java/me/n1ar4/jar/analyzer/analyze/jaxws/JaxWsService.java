/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.analyze.jaxws;

import me.n1ar4.jar.analyzer.analyze.jaxws.asm.JaxWsClassVisitor;
import me.n1ar4.jar.analyzer.core.reference.ClassReference;
import me.n1ar4.jar.analyzer.core.reference.MethodReference;
import me.n1ar4.jar.analyzer.engine.EngineConst;
import me.n1ar4.jar.analyzer.engine.log.LogManager;
import me.n1ar4.jar.analyzer.engine.log.Logger;
import me.n1ar4.jar.analyzer.engine.utils.StackMapFrameHandler;
import me.n1ar4.jar.analyzer.entity.ClassFileEntity;
import org.objectweb.asm.ClassReader;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class JaxWsService {
    private static final Logger logger = LogManager.getLogger();

    public static void start(Set<ClassFileEntity> classFileList,
                             List<JaxWsEndpoint> endpoints,
                             Map<ClassReference.Handle, ClassReference> classMap,
                             Map<MethodReference.Handle, MethodReference> methodMap) {
        for (ClassFileEntity file : classFileList) {
            try {
                JaxWsClassVisitor mcv = new JaxWsClassVisitor(endpoints, classMap, methodMap);
                ClassReader cr = new ClassReader(file.getFile());
                cr.accept(mcv, EngineConst.AnalyzeASMOptions);
            } catch (IndexOutOfBoundsException e) {
                if (!StackMapFrameHandler.handleParseException(file,
                        new JaxWsClassVisitor(endpoints, classMap, methodMap),
                        logger, "jax-ws analysis", e)) {
                    ByteArrayOutputStream bao = new ByteArrayOutputStream();
                    PrintWriter ps = new PrintWriter(bao);
                    e.printStackTrace(ps);
                    ps.flush();
                    ps.close();
                    logger.error("#################### JAX-WS ANALYZE ERROR ####################");
                    logger.error("{}", bao);
                }
            } catch (Exception e) {
                ByteArrayOutputStream bao = new ByteArrayOutputStream();
                PrintWriter ps = new PrintWriter(bao);
                e.printStackTrace(ps);
                ps.flush();
                ps.close();
                logger.error("#################### JAX-WS ANALYZE ERROR ####################");
                logger.error("{}", bao);
            }
        }
    }
}
