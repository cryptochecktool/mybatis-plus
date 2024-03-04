/*
 * Copyright (c) 2011-2023, baomidou (jobob@qq.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.baomidou.mybatisplus.core.handlers;

import java.lang.reflect.Field;

/**
 * Json类型处理器接口(实现类确保为多例状态).
 *
 * @author nieqiurong 2024年3月4日
 * @since 3.5.6
 */
public interface IJsonTypeHandler<T> {

    void init(Field field);

    T parse(String json);

    String toJson(Object obj);

}
