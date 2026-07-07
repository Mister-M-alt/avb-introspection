/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * On-disk persistence (BE-8): uploaded pcaps and sessions live under the
 * data directory and survive backend restarts. Layout:
 *   <data>/users.json                  (owned by Auth)
 *   <data>/meta.json                   (metadata, id counters, domains)
 *   <data>/pcaps/<id>.pcap             (upload library, "default" domain)
 *   <data>/pcaps/domains/<dom>/<id>.pcap (upload library, other domains)
 *   <data>/sessions/<id>/capture.pcap  (the session's own pcap copy)
 *   <data>/sessions/<id>/notes.md      (user-edited investigation notes)
 *   <data>/security.log                (append-only security alerts, JSONL)
 *
 * A session folder is self-contained: deleting the library upload (or the
 * original server path) never breaks an existing investigation.
 *
 * Domains (SE-5): every pcap, session, folder and device name belongs to
 * exactly one domain. Domain ids are validated slugs, unique by
 * construction, and each non-default domain keeps its pcap files in its own
 * subtree — two domains can never overlap on disk or in metadata.
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
        std::string domain = "default";
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
        std::string domain = "default";
    };
    struct SessionSource {
        std::string pcapId, name, alias;
    };
    struct DomainMeta {
        std::string id, name, owner, createdAt;
    };

    bool init(const std::string& dataDir, std::string& err);

    const std::string& dataDir() const { return mDataDir; }
    std::string usersFile() const { return mDataDir + "/users.json"; }

    // ------------------------------------------------------------ domains -
    /** Valid domain id: ^[a-z][a-z0-9-]{0,31}$ and not a reserved word. */
    static bool validDomainId(const std::string& id);
    std::vector<DomainMeta> domains() const; // includes the built-in "default"
    bool hasDomain(const std::string& id) const;
    std::string domainOwner(const std::string& id) const;
    bool addDomain(const std::string& id, const std::string& name,
                   const std::string& owner, std::string& err);
    /** Delete a domain. Without `force` it must hold no pcaps or sessions.
     *  With `force` its data is removed too; the ids of removed sessions are
     *  returned so the caller can drop them from the analysis engine. */
    bool removeDomain(const std::string& id, bool force,
                      std::vector<std::string>& removedSessions,
                      std::string& err);

    /** Persist an uploaded pcap into `folder` ("" = root) of `domain`;
     *  returns its id ("" on error). A new folder name is created
     *  implicitly. */
    std::string addPcap(const std::string& name, const std::string& bytes,
                        const std::string& folder, const std::string& domain,
                        std::string& err);
    std::vector<PcapMeta> pcaps() const;                          // all domains
    std::vector<PcapMeta> pcaps(const std::string& domain) const; // one domain
    bool hasPcap(const std::string& id) const;
    /** Domain the pcap belongs to; "" when the id is unknown. */
    std::string pcapDomain(const std::string& id) const;
    std::string pcapPath(const std::string& id) const;
    std::string pcapName(const std::string& id) const;
    /** Delete a stored pcap (file + metadata). Sessions keep their own copy. */
    bool removePcap(const std::string& id, std::string& err);

    /** Library folders (flat, per domain). A folder exists explicitly
     *  (addPcapFolder) or implicitly while a pcap is filed in it. */
    std::vector<std::string> pcapFolders(const std::string& domain) const;
    bool addPcapFolder(const std::string& domain, const std::string& name,
                       std::string& err);
    bool removePcapFolder(const std::string& domain, const std::string& name,
                          std::string& err); // empty only
    bool setPcapFolder(const std::string& id, const std::string& folder,
                       std::string& err); // "" moves back to the root

    /** Directory holding the library pcap files. Configurable by the admin;
     *  defaults to <data>/pcaps. Changing it migrates the stored files
     *  (all domains — each keeps its subtree under the new root). */
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
    /** Domain the session belongs to; "" when the id is unknown. */
    std::string sessionDomain(const std::string& id) const;

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
     *  Per domain — the same MAC may carry different names in different
     *  domains (devices.json). */
    std::map<std::string, std::string> deviceNames(
        const std::string& domain) const;
    bool setDeviceName(const std::string& domain, const std::string& mac,
                       const std::string& name,
                       std::string& err); // empty name removes the entry

    static std::string nowIso8601();

private:
    bool save(std::string& err);

    bool saveDeviceNames(std::string& err);

    std::string pcapRootLocked() const {
        return mPcapRoot.empty() ? mDataDir + "/pcaps" : mPcapRoot;
    }
    /** Path of a pcap file relative to the root: the default domain keeps
     *  the flat v1 layout, every other domain gets its own subtree. */
    static std::string pcapRelPath(const PcapMeta& p) {
        return (p.domain == "default" ? "" : "domains/" + p.domain + "/") +
               p.id + ".pcap";
    }
    std::string pcapPathLocked(const PcapMeta& p) const {
        return pcapRootLocked() + "/" + pcapRelPath(p);
    }
    std::string pcapPathLocked(const std::string& id) const {
        for (auto& p : mPcaps)
            if (p.id == id) return pcapPathLocked(p);
        return pcapRootLocked() + "/" + id + ".pcap";
    }

    std::string mDataDir;
    mutable std::mutex mMu;
    uint64_t mNextPcap = 1, mNextSession = 1;
    std::vector<PcapMeta> mPcaps;
    std::vector<SessionMeta> mSessions;
    // domain -> (mac -> name)
    std::map<std::string, std::map<std::string, std::string>> mDeviceNames;
    // explicitly created folders as (domain, name), sorted
    std::vector<std::pair<std::string, std::string>> mPcapFolders;
    std::vector<DomainMeta> mDomains; // non-default domains
    std::string mPcapRoot;            // "" = default <data>/pcaps
};

} // namespace avb
