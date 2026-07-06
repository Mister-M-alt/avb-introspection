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
        std::string folder; // library folder ("" = root; flat, no nesting)
    };
    struct SessionMeta {
        std::string id, name, pcapId, path, createdAt;
        // When a session combines several library pcaps into one timeline, all
        // source ids are recorded here (pcapId holds the first for back-compat),
        // each with a user-editable display alias (parallel to pcapIds).
        std::vector<std::string> pcapIds;
        std::vector<std::string> pcapAliases;
        // Transient (never persisted): when the API pre-processed the source
        // (e.g. decompressed a compressed capture), copy from here while
        // `path` keeps recording the user-visible origin.
        std::string resolvedPath;
    };
    struct SessionSource {
        std::string pcapId, name, alias;
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
    /** Delete a stored pcap (file + metadata). Sessions keep their own copy. */
    bool removePcap(const std::string& id, std::string& err);

    /** Library folders (flat). A folder exists explicitly (addPcapFolder) or
     *  implicitly while a pcap is filed in it. */
    std::vector<std::string> pcapFolders() const;
    bool addPcapFolder(const std::string& name, std::string& err);
    bool removePcapFolder(const std::string& name, std::string& err); // empty only
    bool setPcapFolder(const std::string& id, const std::string& folder,
                       std::string& err); // "" moves back to the root

    /** Directory holding the library pcap files. Configurable by the admin;
     *  defaults to <data>/pcaps. Changing it migrates the stored files. */
    std::string pcapRoot() const;
    std::string defaultPcapRoot() const { return mDataDir + "/pcaps"; }
    bool setPcapRoot(const std::string& path, std::string& err);

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
    std::string sessionSrcMapPath(const std::string& id) const;
    std::string sessionNotesPath(const std::string& id) const;

    /** Source captures a session was built from, with display aliases. Empty
     *  for a single-capture session with no recorded sources. */
    std::vector<SessionSource> sessionSources(const std::string& id) const;
    /** Rename source #index's alias (persisted). */
    bool setSessionAlias(const std::string& id, size_t index,
                         const std::string& alias, std::string& err);

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

    std::string pcapRootLocked() const {
        return mPcapRoot.empty() ? mDataDir + "/pcaps" : mPcapRoot;
    }
    std::string pcapPathLocked(const std::string& id) const {
        return pcapRootLocked() + "/" + id + ".pcap";
    }

    std::string mDataDir;
    mutable std::mutex mMu;
    uint64_t mNextPcap = 1, mNextSession = 1;
    std::vector<PcapMeta> mPcaps;
    std::vector<SessionMeta> mSessions;
    std::map<std::string, std::string> mDeviceNames;
    std::vector<std::string> mPcapFolders; // explicitly created folders
    std::string mPcapRoot;                 // "" = default <data>/pcaps
};

} // namespace avb
