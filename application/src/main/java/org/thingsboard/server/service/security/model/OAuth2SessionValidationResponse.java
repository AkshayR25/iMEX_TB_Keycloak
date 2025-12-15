/**
 * Copyright © 2016-2025 The Thingsboard Authors
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
package org.thingsboard.server.service.security.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Schema
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2SessionValidationResponse {

    @Schema(description = "Whether the OAuth2 session is valid", required = true)
    private boolean valid;

    @Schema(description = "Reason for invalid session", required = false)
    private String reason;

    @Schema(description = "Whether the user has changed in the OAuth2 provider", required = false)
    private boolean userChanged;

    @Schema(description = "New access token if session was refreshed", required = false)
    private String newAccessToken;

    @Schema(description = "New refresh token if session was refreshed", required = false)
    private String newRefreshToken;
}
