#include "isolate.hpp"

#include <cocaine/context.hpp>
#include <cocaine/logging.hpp>
#include <cocaine/memory.hpp>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <system_error>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/lexical_cast.hpp>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace cocaine;
using namespace cocaine::isolate;

namespace fs = boost::filesystem;

namespace {

struct container_handle_t:
    public api::handle_t
{
    container_handle_t(const docker::container_t& container):
        m_container(container)
    { }

    virtual
   ~container_handle_t() {
        terminate();
    }

    void
    start(const std::vector<std::string>& binds) {
        m_container.start(binds);
    }

    void
    attach() {
        m_connection = m_container.attach();
    }

    virtual
    void
    terminate() {
        try {
            m_container.kill();
        } catch (...) {
            // pass
        }

        try {
            m_container.remove();
        } catch (...) {
            // pass
        }
    }

    virtual
    int
    stdout() const {
        return m_connection.fd();
    }

private:
    docker::container_t m_container;
    docker::connection_t m_connection;
};

}

docker_t::docker_t(context_t& context,
                   const std::string& name,
                   const Json::Value& args):
    category_type(context, name, args),
    m_log(new logging::log_t(context, name)),
    m_docker_client(
        docker::endpoint_t::from_string(args.get("endpoint", "tcp://127.0.0.1:4243").asString()),
        m_log
    )
{
    rapidjson::Document info;
    m_docker_client.inspect_image(name, info);
    if (info.IsNull()) {
        m_docker_client.pull_image(args.get("registry", "").asString(),
                                   name,
                                   args.get("tag", "").asString());
    }

    m_run_config.SetObject();

    m_run_config.AddMember("Hostname", "", m_json_allocator);
    m_run_config.AddMember("User", "", m_json_allocator);
    m_run_config.AddMember("Memory", unsigned(args.get("memory_limit", 0).asUInt64()), m_json_allocator);
    m_run_config.AddMember("MemorySwap", unsigned(args.get("memory_swap", 0).asUInt64()), m_json_allocator);
    m_run_config.AddMember("AttachStdin", false, m_json_allocator);
    m_run_config.AddMember("AttachStdout", false, m_json_allocator);
    m_run_config.AddMember("AttachStderr", false, m_json_allocator);
    rapidjson::Value v1;
    m_run_config.AddMember("PortSpecs", v1, m_json_allocator);
    m_run_config.AddMember("Tty", false, m_json_allocator);
    m_run_config.AddMember("OpenStdin", false, m_json_allocator);
    m_run_config.AddMember("StdinOnce", false, m_json_allocator);
    rapidjson::Value v2(rapidjson::kArrayType);
    m_run_config.AddMember("Env", v2, m_json_allocator);
    rapidjson::Value v3(rapidjson::kArrayType);
    m_run_config.AddMember("Cmd", v3, m_json_allocator);
    rapidjson::Value v4;
    m_run_config.AddMember("Dns", v4, m_json_allocator);
    m_run_config.AddMember("Image", name.data(), m_json_allocator);
    rapidjson::Value v5(rapidjson::kObjectType);
    m_run_config.AddMember("Volumes", v5, m_json_allocator);
    m_run_config.AddMember("VolumesFrom", "", m_json_allocator);
    m_run_config.AddMember("WorkingDir", "", m_json_allocator);
}

docker_t::~docker_t() {
    // pass
}

std::unique_ptr<api::handle_t>
docker_t::spawn(const std::string& path,
                const api::string_map_t& args,
                const api::string_map_t& environment)
{
    auto& env = m_run_config["Env"];
    env.SetArray();
    for (auto it = environment.begin(); it != environment.end(); ++it) {
        env.PushBack((it->first + "=" + it->second).c_str(), m_json_allocator);
    }

    auto& cmd = m_run_config["Cmd"];
    cmd.SetArray();
    cmd.PushBack(path.c_str(), m_json_allocator);
    for (auto it = environment.begin(); it != environment.end(); ++it) {
        cmd.PushBack(it->first.c_str(), m_json_allocator);
        cmd.PushBack(it->second.c_str(), m_json_allocator);
    }

    fs::path working_dir(path);
    working_dir.remove_filename();
    m_run_config["WorkingDir"].SetString(working_dir.c_str());

    std::vector<std::string> binds;
    std::string socket_dir(fs::path(args.at("endpoint")).remove_filename().c_str());
    binds.emplace_back((socket_dir + ":" + socket_dir).c_str());

    std::unique_ptr<container_handle_t> handle(
        new container_handle_t(m_docker_client.create_container(m_run_config))
    );

    handle->start(binds);
    handle->attach();

    return std::move(handle);
}