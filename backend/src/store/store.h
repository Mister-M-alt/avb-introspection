/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * On-disk persistence (BE-8): uploaded pcaps and sessions live under the
 * data directory and survive backend restarts. Layout:
 *   <data>/users.json                  (owned by Auth)
 *   <data>/meta.json                   (metadata, id counters)
 *   <data>/pcaps/<id>.pcap             (upload library)
 *   <data>/sessions/<id>/capture.pcap  (the session's own pcap copy)
 *   <data>/sessions/<id>/notes.md      (user-edited investigation notes)
 *
 * A session folder is self-contained: deleting the library upload (or the
 * original server path) never breaks an existing investigation.
 */
#pragma once

#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace avb {

class Store {
public:
    struct PcapMeta {
        std::string id, name, uploadedAt;
        uint64_t size = 0;
    };
    struct SessionMeta {
        std::string id, name, pcapId, path, createdAt;
    };

    bool init(const std::string& dataDir, std::string& err);

    const std::string& dataDir() const { return mDataDir; }
    std::string usersFile() const { return mDataDir + "/users.json"; }

    /** Persist an uploaded pcap; returns its id ("" on error). */
    std::string addPcap(const std::string& name, const std::string& bytes,
                        std::string& err);
    std::vector<PcapMeta> pcaps() const;
    bool hasPcap(const std::string& id) const;
    std::string pcapPath(const std::string& id) const;
    std::string pcapName(const std::string& id) const;

    /**
     * Create the session folder: assigns the id, copies the source capture
     * (library pcap or server path) to capture.pcap, seeds notes.md, and
     * persists the metadata. Returns the id, or "" with err set.
     */
    std::string addSession(SessionMeta meta, std::string& err);
    void removeSession(const std::string& id); // deletes the whole folder
    std::vector<SessionMeta> sessions() const;

    std::string sessionDir(const std::string& id) const;
    std::string sessionPcapPath(const std::string& id) const;
    std::string sessionNotesPath(const std::string& id) const;

    /** Investigation notes (markdown). Read returns "" when absent. */
    std::string readNotes(const std::string& id) const;
    bool writeNotes(const std::string& id, const std::string& markdown,
                    std::string& err);

    /** User-assigned device names, keyed by MAC ("aa:bb:cc:dd:ee:ff").
     *  Global — a device keeps its name across sessions (devices.json). */
    std::map<std::string, std::string> deviceNames() const;
    bool setDeviceName(const std::string& mac, const std::string& name,
                       std::string& err); // empty name removes the entry

    static std::string nowIso8601();

private:
    bool save(std::string& err);

    bool saveDeviceNames(std::string& err);

    std::string mDataDir;
    mutable std::mutex mMu;
    uint64_t mNextPcap = 1, mNextSession = 1;
    std::vector<PcapMeta> mPcaps;
    std::vector<SessionMeta> mSessions;
    std::map<std::string, std::string> mDeviceNames;
};

} // namespace avb
