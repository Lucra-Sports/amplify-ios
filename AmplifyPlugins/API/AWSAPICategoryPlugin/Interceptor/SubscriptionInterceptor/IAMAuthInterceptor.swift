//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import AWSCore
import AWSPluginsCore
import Amplify
import AppSyncRealTimeClient

class IAMAuthInterceptor: AuthInterceptor {

    let authProvider: AWSCredentialsProvider
    let region: AWSRegionType

    init(_ authProvider: AWSCredentialsProvider, region: AWSRegionType) {
        self.authProvider = authProvider
        self.region = region
    }

    func interceptMessage(_ message: AppSyncMessage, for endpoint: URL) -> AppSyncMessage {
        switch message.messageType {
        case .subscribe:
            let authHeader = getAuthHeader(endpoint, with: message.payload?.data ?? "")
            var payload = message.payload ?? AppSyncMessage.Payload()
            payload.authHeader = authHeader
            let signedMessage = AppSyncMessage(id: message.id,
                                               payload: payload,
                                               type: message.messageType)
            return signedMessage
        default:
            Amplify.API.log.verbose("Message type does not need signing - \(message.messageType)")
        }
        return message
    }

    func interceptConnection(_ request: AppSyncConnectionRequest,
                             for endpoint: URL) -> AppSyncConnectionRequest {
        let url = endpoint.appendingPathComponent(RealtimeProviderConstants.iamConnectPath)
        let payloadString = SubscriptionConstants.emptyPayload
        guard let authHeader = getAuthHeader(url, with: payloadString) else {
            return request
        }
        let base64Auth = AppSyncJSONHelper.base64AuthenticationBlob(authHeader)

        let payloadData = payloadString.data(using: .utf8)
        let payloadBase64 = payloadData?.base64EncodedString()

        guard var urlComponents = URLComponents(url: request.url, resolvingAgainstBaseURL: false) else {
            return request
        }
        let headerQuery = URLQueryItem(name: RealtimeProviderConstants.header, value: base64Auth)
        let payloadQuery = URLQueryItem(name: RealtimeProviderConstants.payload, value: payloadBase64)
        urlComponents.queryItems = [headerQuery, payloadQuery]
        guard let signedUrl = urlComponents.url else {
            return request
        }
        let signedRequest = AppSyncConnectionRequest(url: signedUrl)
        return signedRequest
    }

    final private func getAuthHeader(_ endpoint: URL, with payload: String) -> IAMAuthenticationHeader? {
        guard let host = endpoint.host else {
            return nil
        }
        let amzDate =  NSDate.aws_clockSkewFixed() as NSDate
        guard let date = amzDate.aws_stringValue(AWSDateISO8601DateFormat2) else {
            return nil
        }
        guard let awsEndpoint = AWSEndpoint(region: region,
                                            serviceName: SubscriptionConstants.appsyncServiceName,
                                            url: endpoint) else {
            return nil
        }
        let signer: AWSSignatureV4Signer = AWSSignatureV4Signer(credentialsProvider: authProvider,
                                                                endpoint: awsEndpoint)
        let semaphore = DispatchSemaphore(value: 0)
        let mutableRequest = NSMutableURLRequest(url: endpoint)
        mutableRequest.httpMethod = "POST"
        mutableRequest.addValue(RealtimeProviderConstants.iamAccept,
                                forHTTPHeaderField: RealtimeProviderConstants.acceptKey)
        mutableRequest.addValue(date, forHTTPHeaderField: RealtimeProviderConstants.amzDate)
        mutableRequest.addValue(RealtimeProviderConstants.iamEncoding,
                                forHTTPHeaderField: RealtimeProviderConstants.contentEncodingKey)
        mutableRequest.addValue(RealtimeProviderConstants.iamConentType,
                                forHTTPHeaderField: RealtimeProviderConstants.contentTypeKey)
        mutableRequest.httpBody = payload.data(using: .utf8)

        signer.interceptRequest(mutableRequest).continueWith { _ in
            semaphore.signal()
            return nil
        }
        semaphore.wait()

        let authHeader = IAMAuthenticationHeader(host: host, allHeaders: mutableRequest.allHTTPHeaderFields)
        return authHeader
    }
}

/// Authentication header for IAM based auth
private class IAMAuthenticationHeader: AuthenticationHeader {
    private static let AuthorizationHeaderKey = SubscriptionConstants.authorizationkey
    private static let AcceptHeaderKey = RealtimeProviderConstants.acceptKey
    private static let ContentEncodingKey = RealtimeProviderConstants.contentEncodingKey
    private static let ContentTypeKey = RealtimeProviderConstants.contentTypeKey
    private static let AmzDateKey = RealtimeProviderConstants.amzDate
    private static let AmzSecurityTokenKey = RealtimeProviderConstants.iamSecurityTokenKey

    private static let LowercasedHeaderKeys: Set = [AuthorizationHeaderKey.lowercased(),
                                                    AcceptHeaderKey.lowercased(),
                                                    ContentEncodingKey.lowercased(),
                                                    ContentTypeKey.lowercased(),
                                                    AmzDateKey.lowercased(),
                                                    AmzSecurityTokenKey.lowercased()]

    let authorization: String
    let securityToken: String
    let date: String
    let accept: String
    let contentEncoding: String
    let contentType: String
    let remainingHeaders: [String: String]?

    convenience init(host: String, allHeaders: [String: String]?) {
        let authorization = allHeaders?[SubscriptionConstants.authorizationkey] ?? ""
        let securityToken = allHeaders?[RealtimeProviderConstants.iamSecurityTokenKey] ?? ""
        let date = allHeaders?[RealtimeProviderConstants.amzDate] ?? ""
        let remainingHeaders = allHeaders?.filter { (header) -> Bool in
            return !Self.LowercasedHeaderKeys.contains(header.key.lowercased())
        }
        self.init(authorization: authorization,
                  host: host,
                  token: securityToken,
                  date: date,
                  accept: RealtimeProviderConstants.iamAccept,
                  contentEncoding: RealtimeProviderConstants.iamEncoding,
                  contentType: RealtimeProviderConstants.iamConentType,
                  remainingHeaders: remainingHeaders)
    }

    init(authorization: String,
         host: String,
         token: String,
         date: String,
         accept: String,
         contentEncoding: String,
         contentType: String,
         remainingHeaders: [String: String]?) {
        self.date = date
        self.authorization = authorization
        self.securityToken = token
        self.accept = accept
        self.contentEncoding = contentEncoding
        self.contentType = contentType
        self.remainingHeaders = remainingHeaders
        super.init(host: host)
    }


    private struct DynamicCodingKeys: CodingKey {
        var stringValue: String
        init?(stringValue: String) {
            self.stringValue = stringValue
        }
        var intValue: Int?
        init?(intValue: Int) {
            return nil
        }
    }

    override func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: DynamicCodingKeys.self)
        try container.encode(authorization,
                             forKey: DynamicCodingKeys(stringValue: IAMAuthenticationHeader.AuthorizationHeaderKey)!)
        try container.encode(accept,
                             forKey: DynamicCodingKeys(stringValue: IAMAuthenticationHeader.AcceptHeaderKey)!)
        try container.encode(contentEncoding,
                             forKey: DynamicCodingKeys(stringValue: IAMAuthenticationHeader.ContentEncodingKey)!)
        try container.encode(contentType,
                             forKey: DynamicCodingKeys(stringValue: IAMAuthenticationHeader.ContentTypeKey)!)
        try container.encode(date,
                             forKey: DynamicCodingKeys(stringValue: IAMAuthenticationHeader.AmzDateKey)!)
        try container.encode(securityToken,
                             forKey: DynamicCodingKeys(stringValue: IAMAuthenticationHeader.AmzSecurityTokenKey)!)
        if let headers = remainingHeaders {
            for (key, value) in headers {
                try container.encode(value, forKey: DynamicCodingKeys(stringValue: key)!)
            }

        }
        try super.encode(to: encoder)
    }
}
