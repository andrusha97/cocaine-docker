#ifndef COCAINE_DOCKER_CLIENT_HPP
#define COCAINE_DOCKER_CLIENT_HPP

#include "http.hpp"

#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <cocaine/common.hpp>
#include <cocaine/logging.hpp>

#include <boost/variant.hpp>
#include <boost/asio.hpp>

namespace cocaine { namespace docker {

class endpoint_t {
public:
    typedef std::pair<std::string, uint16_t>
            tcp_endpoint_t;

    typedef std::string
            unix_endpoint_t;

    static
    endpoint_t
    from_string(const std::string& endpoint);

    endpoint_t();

    endpoint_t(const tcp_endpoint_t& e);

    endpoint_t(const unix_endpoint_t& e);

    bool
    is_unix() const;

    bool
    is_tcp() const;

    const std::string&
    get_host() const;

    uint16_t
    get_port() const;

    const std::string&
    get_path() const;

    std::string
    to_string() const;

private:
    typedef boost::variant<unix_endpoint_t, tcp_endpoint_t>
            variant_t;

    mutable variant_t m_value;
};

class connection_t {
public:
    typedef boost::asio::local::stream_protocol::socket
            unix_socket_t;

    typedef boost::asio::ip::tcp::socket
            tcp_socket_t;

    connection_t() {
        // pass
    }

    connection_t(boost::asio::io_service& ioservice,
                 const endpoint_t& endpoint);

    void
    connect(boost::asio::io_service& ioservice,
            const endpoint_t& endpoint);

    bool
    is_unix() const;

    bool
    is_tcp() const;

    std::shared_ptr<unix_socket_t>
    get_unix() const;

    std::shared_ptr<tcp_socket_t>
    get_tcp() const;

    int
    fd() const;

private:
    typedef boost::variant<std::shared_ptr<unix_socket_t>, std::shared_ptr<tcp_socket_t>>
            variant_t;

    mutable variant_t m_socket;
};

class client_impl_t {
public:
    client_impl_t(const endpoint_t& endpoint) :
        m_ioservice_ref(m_ioservice),
        m_endpoint(endpoint)
    {
        // pass
    }

    client_impl_t(boost::asio::io_service& ioservice,
                  const endpoint_t& endpoint) :
        m_ioservice_ref(ioservice),
        m_endpoint(endpoint)
    {
        // pass
    }

    http_response_t
    post(const std::string& uri,
         const http_headers_t& headers,
         const rapidjson::Value& body);

    http_response_t
    get(const std::string& uri,
        const http_headers_t& headers);

    http_response_t
    del(const std::string& uri,
        const http_headers_t& headers);

    connection_t
    post_nobody(http_response_t& response,
                const std::string& uri,
                const http_headers_t& headers);

private:
    http_response_t
    request(const http_request_t& request);

    // it doesn't support sending of body with request (even if method is POST) and doesn't read body from reply
    connection_t
    request_nobody(http_response_t& response,
                   const http_request_t& request);

private:
    boost::asio::io_service m_ioservice; // may be not used
    boost::asio::io_service& m_ioservice_ref;
    endpoint_t m_endpoint;
};

class container_t {
public:
    container_t(const std::string& id,
                std::shared_ptr<client_impl_t> client,
                std::shared_ptr<logging::log_t> logger) :
        m_id(id),
        m_client(client),
        m_logger(logger)
    {
        // pass
    }

    const std::string&
    id() const {
        return m_id;
    }

    void
    start(const std::vector<std::string>& binds = std::vector<std::string>());

    void
    kill();

    void
    stop(unsigned int timeout);

    void
    remove(bool volumes = false);

    connection_t
    attach();

private:
    std::string m_id;

    std::shared_ptr<client_impl_t> m_client;
    std::shared_ptr<logging::log_t> m_logger;
};

class client_t
{
public:
    client_t(const endpoint_t& endpoint,
             std::shared_ptr<logging::log_t> logger) :
        m_client(new client_impl_t(endpoint)),
        m_logger(logger)
    {
        // pass
    }

    void
    inspect_image(const std::string& image,
                  rapidjson::Document& result);

    void
    pull_image(const std::string& registry,
               const std::string& image,
               const std::string& tag);

    container_t
    create_container(const rapidjson::Value& args);

private:
    std::shared_ptr<client_impl_t> m_client;
    std::shared_ptr<logging::log_t> m_logger;
};

}} // namespace cocaine::docker

#endif // COCAINE_DOCKER_CLIENT_HPP