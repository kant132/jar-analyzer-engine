/*
 * GPLv3 License
 *
 * Copyright (c) 2022-2026 4ra1n (Jar Analyzer Team)
 *
 * This project is distributed under the GPLv3 license.
 *
 * https://github.com/jar-analyzer/jar-analyzer/blob/master/LICENSE
 */

package me.n1ar4.jar.analyzer.analyze.jaxrs;

public interface JaxRsConstant {
    String JAVAX_PREFIX = "Ljavax/ws/rs/";
    String JAKARTA_PREFIX = "Ljakarta/ws/rs/";

    String JAVAX_PATH_ANNO = JAVAX_PREFIX + "Path;";
    String JAKARTA_PATH_ANNO = JAKARTA_PREFIX + "Path;";

    String JAVAX_GET_ANNO = JAVAX_PREFIX + "GET;";
    String JAKARTA_GET_ANNO = JAKARTA_PREFIX + "GET;";

    String JAVAX_POST_ANNO = JAVAX_PREFIX + "POST;";
    String JAKARTA_POST_ANNO = JAKARTA_PREFIX + "POST;";

    String JAVAX_PUT_ANNO = JAVAX_PREFIX + "PUT;";
    String JAKARTA_PUT_ANNO = JAKARTA_PREFIX + "PUT;";

    String JAVAX_DELETE_ANNO = JAVAX_PREFIX + "DELETE;";
    String JAKARTA_DELETE_ANNO = JAKARTA_PREFIX + "DELETE;";

    String JAVAX_PATCH_ANNO = JAVAX_PREFIX + "PATCH;";
    String JAKARTA_PATCH_ANNO = JAKARTA_PREFIX + "PATCH;";
}
