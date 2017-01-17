



<!DOCTYPE html>
<html lang="en" class="">
  <head prefix="og: http://ogp.me/ns# fb: http://ogp.me/ns/fb# object: http://ogp.me/ns/object# article: http://ogp.me/ns/article# profile: http://ogp.me/ns/profile#">
    <meta charset='utf-8'>
    

    <link crossorigin="anonymous" href="https://assets-cdn.github.com/assets/frameworks-c07e6f4b02b556d1d85052fb3853caf84c80e6b23dcdb1ae1b00f051da1115a2.css" media="all" rel="stylesheet" />
    <link crossorigin="anonymous" href="https://assets-cdn.github.com/assets/github-c1778c4802d4029d4b6cda1d8b4bf3d900b36752832715d2d2895ea63cf05de2.css" media="all" rel="stylesheet" />
    
    
    <link crossorigin="anonymous" href="https://assets-cdn.github.com/assets/site-293f92180d0a619a750fa2b5eae9e36740f5723a59c0ec308972c70d24e834fc.css" media="all" rel="stylesheet" />
    

    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta http-equiv="Content-Language" content="en">
    <meta name="viewport" content="width=device-width">
    
    <title>boulder/safebrowsing.pb.go at 3dcf4de4b4a42f227df61dff562d5f5958cfa85a · cpu/boulder · GitHub</title>
    <link rel="search" type="application/opensearchdescription+xml" href="/opensearch.xml" title="GitHub">
    <link rel="fluid-icon" href="https://github.com/fluidicon.png" title="GitHub">
    <link rel="apple-touch-icon" href="/apple-touch-icon.png">
    <link rel="apple-touch-icon" sizes="57x57" href="/apple-touch-icon-57x57.png">
    <link rel="apple-touch-icon" sizes="60x60" href="/apple-touch-icon-60x60.png">
    <link rel="apple-touch-icon" sizes="72x72" href="/apple-touch-icon-72x72.png">
    <link rel="apple-touch-icon" sizes="76x76" href="/apple-touch-icon-76x76.png">
    <link rel="apple-touch-icon" sizes="114x114" href="/apple-touch-icon-114x114.png">
    <link rel="apple-touch-icon" sizes="120x120" href="/apple-touch-icon-120x120.png">
    <link rel="apple-touch-icon" sizes="144x144" href="/apple-touch-icon-144x144.png">
    <link rel="apple-touch-icon" sizes="152x152" href="/apple-touch-icon-152x152.png">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon-180x180.png">
    <meta property="fb:app_id" content="1401488693436528">

      <meta content="https://avatars2.githubusercontent.com/u/292650?v=3&amp;s=400" name="twitter:image:src" /><meta content="@github" name="twitter:site" /><meta content="summary" name="twitter:card" /><meta content="cpu/boulder" name="twitter:title" /><meta content="boulder - An ACME-based CA, written in Go." name="twitter:description" />
      <meta content="https://avatars2.githubusercontent.com/u/292650?v=3&amp;s=400" property="og:image" /><meta content="GitHub" property="og:site_name" /><meta content="object" property="og:type" /><meta content="cpu/boulder" property="og:title" /><meta content="https://github.com/cpu/boulder" property="og:url" /><meta content="boulder - An ACME-based CA, written in Go." property="og:description" />
      <meta name="browser-stats-url" content="https://api.github.com/_private/browser/stats">
    <meta name="browser-errors-url" content="https://api.github.com/_private/browser/errors">
    <link rel="assets" href="https://assets-cdn.github.com/">
    
    <meta name="pjax-timeout" content="1000">
    
    <meta name="request-id" content="6BB3FA31:1D99:181B1F0A:587E6C75" data-pjax-transient>

    <meta name="msapplication-TileImage" content="/windows-tile.png">
    <meta name="msapplication-TileColor" content="#ffffff">
    <meta name="selected-link" value="repo_source" data-pjax-transient>

    <meta name="google-site-verification" content="KT5gs8h0wvaagLKAVWq8bbeNwnZZK1r1XQysX3xurLU">
<meta name="google-site-verification" content="ZzhVyEFwb7w3e0-uOTltm8Jsck2F5StVihD0exw2fsA">
    <meta name="google-analytics" content="UA-3769691-2">

<meta content="collector.githubapp.com" name="octolytics-host" /><meta content="github" name="octolytics-app-id" /><meta content="6BB3FA31:1D99:181B1F0A:587E6C75" name="octolytics-dimension-request_id" />
<meta content="/&lt;user-name&gt;/&lt;repo-name&gt;/blob/show" data-pjax-transient="true" name="analytics-location" />



  <meta class="js-ga-set" name="dimension1" content="Logged Out">



        <meta name="hostname" content="github.com">
    <meta name="user-login" content="">

        <meta name="expected-hostname" content="github.com">
      <meta name="js-proxy-site-detection-payload" content="ODBmNWJkNjM5MmE5NmE0ZDlhNDBhNjJkODgyZjQzMTIxNGFjNzZkYWQ2YzA1N2E4YjFjNjllYmNhNDQ2MWU5OXx7InJlbW90ZV9hZGRyZXNzIjoiMTA3LjE3OS4yNTAuNDkiLCJyZXF1ZXN0X2lkIjoiNkJCM0ZBMzE6MUQ5OToxODFCMUYwQTo1ODdFNkM3NSIsInRpbWVzdGFtcCI6MTQ4NDY4MDMwOSwiaG9zdCI6ImdpdGh1Yi5jb20ifQ==">


      <link rel="mask-icon" href="https://assets-cdn.github.com/pinned-octocat.svg" color="#000000">
      <link rel="icon" type="image/x-icon" href="https://assets-cdn.github.com/favicon.ico">

    <meta name="html-safe-nonce" content="3a3033f398e6ff3b757ff4eaa445b2c97bc39e38">

    <meta http-equiv="x-pjax-version" content="b23642781c6e1a8e1175a8f3b29e82a6">
    

      
  <meta name="description" content="boulder - An ACME-based CA, written in Go.">
  <meta name="go-import" content="github.com/cpu/boulder git https://github.com/cpu/boulder.git">

  <meta content="292650" name="octolytics-dimension-user_id" /><meta content="cpu" name="octolytics-dimension-user_login" /><meta content="59311713" name="octolytics-dimension-repository_id" /><meta content="cpu/boulder" name="octolytics-dimension-repository_nwo" /><meta content="true" name="octolytics-dimension-repository_public" /><meta content="true" name="octolytics-dimension-repository_is_fork" /><meta content="28283593" name="octolytics-dimension-repository_parent_id" /><meta content="letsencrypt/boulder" name="octolytics-dimension-repository_parent_nwo" /><meta content="28283593" name="octolytics-dimension-repository_network_root_id" /><meta content="letsencrypt/boulder" name="octolytics-dimension-repository_network_root_nwo" />
  <link href="https://github.com/cpu/boulder/commits/3dcf4de4b4a42f227df61dff562d5f5958cfa85a.atom" rel="alternate" title="Recent Commits to boulder:3dcf4de4b4a42f227df61dff562d5f5958cfa85a" type="application/atom+xml">


      <link rel="canonical" href="https://github.com/cpu/boulder/blob/3dcf4de4b4a42f227df61dff562d5f5958cfa85a/test/gsb-test-srv/proto/safebrowsing.pb.go" data-pjax-transient>
  </head>


  <body class="logged-out  env-production  vis-public fork page-blob">
    <div id="js-pjax-loader-bar" class="pjax-loader-bar"><div class="progress"></div></div>
    <a href="#start-of-content" tabindex="1" class="accessibility-aid js-skip-to-content">Skip to content</a>

    
    
    



          <header class="site-header js-details-container Details alt-body-font" role="banner">
  <div class="container-responsive">
    <a class="header-logo-invertocat" href="https://github.com/" aria-label="Homepage" data-ga-click="(Logged out) Header, go to homepage, icon:logo-wordmark">
      <svg aria-hidden="true" class="octicon octicon-mark-github" height="32" version="1.1" viewBox="0 0 16 16" width="32"><path fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
    </a>

    <button class="btn-link float-right site-header-toggle js-details-target" type="button" aria-label="Toggle navigation">
      <svg aria-hidden="true" class="octicon octicon-three-bars" height="24" version="1.1" viewBox="0 0 12 16" width="18"><path fill-rule="evenodd" d="M11.41 9H.59C0 9 0 8.59 0 8c0-.59 0-1 .59-1H11.4c.59 0 .59.41.59 1 0 .59 0 1-.59 1h.01zm0-4H.59C0 5 0 4.59 0 4c0-.59 0-1 .59-1H11.4c.59 0 .59.41.59 1 0 .59 0 1-.59 1h.01zM.59 11H11.4c.59 0 .59.41.59 1 0 .59 0 1-.59 1H.59C0 13 0 12.59 0 12c0-.59 0-1 .59-1z"/></svg>
    </button>

    <div class="site-header-menu">
      <nav class="site-header-nav site-header-nav-main">
        <a href="/personal" class="js-selected-navigation-item nav-item nav-item-personal" data-ga-click="Header, click, Nav menu - item:personal" data-selected-links="/personal /personal">
          Personal
</a>        <a href="/open-source" class="js-selected-navigation-item nav-item nav-item-opensource" data-ga-click="Header, click, Nav menu - item:opensource" data-selected-links="/open-source /open-source">
          Open source
</a>        <a href="/business" class="js-selected-navigation-item nav-item nav-item-business" data-ga-click="Header, click, Nav menu - item:business" data-selected-links="/business /business/partners /business/features /business/customers /business">
          Business
</a>        <a href="/explore" class="js-selected-navigation-item nav-item nav-item-explore" data-ga-click="Header, click, Nav menu - item:explore" data-selected-links="/explore /trending /trending/developers /integrations /integrations/feature/code /integrations/feature/collaborate /integrations/feature/ship /showcases /explore">
          Explore
</a>      </nav>

      <div class="site-header-actions">
            <a class="btn btn-primary site-header-actions-btn" href="/join?source=header-repo" data-ga-click="(Logged out) Header, clicked Sign up, text:sign-up">Sign up</a>
          <a class="btn site-header-actions-btn mr-1" href="/login?return_to=%2Fcpu%2Fboulder%2Fblob%2F3dcf4de4b4a42f227df61dff562d5f5958cfa85a%2Ftest%2Fgsb-test-srv%2Fproto%2Fsafebrowsing.pb.go" data-ga-click="(Logged out) Header, clicked Sign in, text:sign-in">Sign in</a>
      </div>

        <nav class="site-header-nav site-header-nav-secondary mr-md-3">
          <a class="nav-item" href="/pricing">Pricing</a>
          <a class="nav-item" href="/blog">Blog</a>
          <a class="nav-item" href="https://help.github.com">Support</a>
          <a class="nav-item header-search-link" href="https://github.com/search">Search GitHub</a>
              <div class="header-search scoped-search site-scoped-search js-site-search" role="search">
  <!-- '"` --><!-- </textarea></xmp> --></option></form><form accept-charset="UTF-8" action="/cpu/boulder/search" class="js-site-search-form" data-scoped-search-url="/cpu/boulder/search" data-unscoped-search-url="/search" method="get"><div style="margin:0;padding:0;display:inline"><input name="utf8" type="hidden" value="&#x2713;" /></div>
    <label class="form-control header-search-wrapper js-chromeless-input-container">
      <div class="header-search-scope">This repository</div>
      <input type="text"
        class="form-control header-search-input js-site-search-focus js-site-search-field is-clearable"
        data-hotkey="s"
        name="q"
        placeholder="Search"
        aria-label="Search this repository"
        data-unscoped-placeholder="Search GitHub"
        data-scoped-placeholder="Search"
        autocapitalize="off">
    </label>
</form></div>

        </nav>
    </div>
  </div>
</header>



    <div id="start-of-content" class="accessibility-aid"></div>

      <div id="js-flash-container">
</div>


    <div role="main">
        <div itemscope itemtype="http://schema.org/SoftwareSourceCode">
    <div id="js-repo-pjax-container" data-pjax-container>
      
<div class="pagehead repohead instapaper_ignore readability-menu experiment-repo-nav">
  <div class="container repohead-details-container">

    

<ul class="pagehead-actions">

  <li>
      <a href="/login?return_to=%2Fcpu%2Fboulder"
    class="btn btn-sm btn-with-count tooltipped tooltipped-n"
    aria-label="You must be signed in to watch a repository" rel="nofollow">
    <svg aria-hidden="true" class="octicon octicon-eye" height="16" version="1.1" viewBox="0 0 16 16" width="16"><path fill-rule="evenodd" d="M8.06 2C3 2 0 8 0 8s3 6 8.06 6C13 14 16 8 16 8s-3-6-7.94-6zM8 12c-2.2 0-4-1.78-4-4 0-2.2 1.8-4 4-4 2.22 0 4 1.8 4 4 0 2.22-1.78 4-4 4zm2-4c0 1.11-.89 2-2 2-1.11 0-2-.89-2-2 0-1.11.89-2 2-2 1.11 0 2 .89 2 2z"/></svg>
    Watch
  </a>
  <a class="social-count" href="/cpu/boulder/watchers"
     aria-label="1 user is watching this repository">
    1
  </a>

  </li>

  <li>
      <a href="/login?return_to=%2Fcpu%2Fboulder"
    class="btn btn-sm btn-with-count tooltipped tooltipped-n"
    aria-label="You must be signed in to star a repository" rel="nofollow">
    <svg aria-hidden="true" class="octicon octicon-star" height="16" version="1.1" viewBox="0 0 14 16" width="14"><path fill-rule="evenodd" d="M14 6l-4.9-.64L7 1 4.9 5.36 0 6l3.6 3.26L2.67 14 7 11.67 11.33 14l-.93-4.74z"/></svg>
    Star
  </a>

    <a class="social-count js-social-count" href="/cpu/boulder/stargazers"
      aria-label="0 users starred this repository">
      0
    </a>

  </li>

  <li>
      <a href="/login?return_to=%2Fcpu%2Fboulder"
        class="btn btn-sm btn-with-count tooltipped tooltipped-n"
        aria-label="You must be signed in to fork a repository" rel="nofollow">
        <svg aria-hidden="true" class="octicon octicon-repo-forked" height="16" version="1.1" viewBox="0 0 10 16" width="10"><path fill-rule="evenodd" d="M8 1a1.993 1.993 0 0 0-1 3.72V6L5 8 3 6V4.72A1.993 1.993 0 0 0 2 1a1.993 1.993 0 0 0-1 3.72V6.5l3 3v1.78A1.993 1.993 0 0 0 5 15a1.993 1.993 0 0 0 1-3.72V9.5l3-3V4.72A1.993 1.993 0 0 0 8 1zM2 4.2C1.34 4.2.8 3.65.8 3c0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2 0 .65-.55 1.2-1.2 1.2zm3 10c-.66 0-1.2-.55-1.2-1.2 0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2 0 .65-.55 1.2-1.2 1.2zm3-10c-.66 0-1.2-.55-1.2-1.2 0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2 0 .65-.55 1.2-1.2 1.2z"/></svg>
        Fork
      </a>

    <a href="/cpu/boulder/network" class="social-count"
       aria-label="203 users forked this repository">
      203
    </a>
  </li>
</ul>

    <h1 class="public ">
  <svg aria-hidden="true" class="octicon octicon-repo-forked" height="16" version="1.1" viewBox="0 0 10 16" width="10"><path fill-rule="evenodd" d="M8 1a1.993 1.993 0 0 0-1 3.72V6L5 8 3 6V4.72A1.993 1.993 0 0 0 2 1a1.993 1.993 0 0 0-1 3.72V6.5l3 3v1.78A1.993 1.993 0 0 0 5 15a1.993 1.993 0 0 0 1-3.72V9.5l3-3V4.72A1.993 1.993 0 0 0 8 1zM2 4.2C1.34 4.2.8 3.65.8 3c0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2 0 .65-.55 1.2-1.2 1.2zm3 10c-.66 0-1.2-.55-1.2-1.2 0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2 0 .65-.55 1.2-1.2 1.2zm3-10c-.66 0-1.2-.55-1.2-1.2 0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2 0 .65-.55 1.2-1.2 1.2z"/></svg>
  <span class="author" itemprop="author"><a href="/cpu" class="url fn" rel="author">cpu</a></span><!--
--><span class="path-divider">/</span><!--
--><strong itemprop="name"><a href="/cpu/boulder" data-pjax="#js-repo-pjax-container">boulder</a></strong>

    <span class="fork-flag">
      <span class="text">forked from <a href="/letsencrypt/boulder">letsencrypt/boulder</a></span>
    </span>
</h1>

  </div>
  <div class="container">
    
<nav class="reponav js-repo-nav js-sidenav-container-pjax"
     itemscope
     itemtype="http://schema.org/BreadcrumbList"
     role="navigation"
     data-pjax="#js-repo-pjax-container">

  <span itemscope itemtype="http://schema.org/ListItem" itemprop="itemListElement">
    <a href="/cpu/boulder" class="js-selected-navigation-item selected reponav-item" data-hotkey="g c" data-selected-links="repo_source repo_downloads repo_commits repo_releases repo_tags repo_branches /cpu/boulder" itemprop="url">
      <svg aria-hidden="true" class="octicon octicon-code" height="16" version="1.1" viewBox="0 0 14 16" width="14"><path fill-rule="evenodd" d="M9.5 3L8 4.5 11.5 8 8 11.5 9.5 13 14 8 9.5 3zm-5 0L0 8l4.5 5L6 11.5 2.5 8 6 4.5 4.5 3z"/></svg>
      <span itemprop="name">Code</span>
      <meta itemprop="position" content="1">
</a>  </span>


  <span itemscope itemtype="http://schema.org/ListItem" itemprop="itemListElement">
    <a href="/cpu/boulder/pulls" class="js-selected-navigation-item reponav-item" data-hotkey="g p" data-selected-links="repo_pulls /cpu/boulder/pulls" itemprop="url">
      <svg aria-hidden="true" class="octicon octicon-git-pull-request" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M11 11.28V5c-.03-.78-.34-1.47-.94-2.06C9.46 2.35 8.78 2.03 8 2H7V0L4 3l3 3V4h1c.27.02.48.11.69.31.21.2.3.42.31.69v6.28A1.993 1.993 0 0 0 10 15a1.993 1.993 0 0 0 1-3.72zm-1 2.92c-.66 0-1.2-.55-1.2-1.2 0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2 0 .65-.55 1.2-1.2 1.2zM4 3c0-1.11-.89-2-2-2a1.993 1.993 0 0 0-1 3.72v6.56A1.993 1.993 0 0 0 2 15a1.993 1.993 0 0 0 1-3.72V4.72c.59-.34 1-.98 1-1.72zm-.8 10c0 .66-.55 1.2-1.2 1.2-.65 0-1.2-.55-1.2-1.2 0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2zM2 4.2C1.34 4.2.8 3.65.8 3c0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2 0 .65-.55 1.2-1.2 1.2z"/></svg>
      <span itemprop="name">Pull requests</span>
      <span class="counter">0</span>
      <meta itemprop="position" content="3">
</a>  </span>

  <a href="/cpu/boulder/projects" class="js-selected-navigation-item reponav-item" data-selected-links="repo_projects new_repo_project repo_project /cpu/boulder/projects">
    <svg aria-hidden="true" class="octicon octicon-project" height="16" version="1.1" viewBox="0 0 15 16" width="15"><path fill-rule="evenodd" d="M10 12h3V2h-3v10zm-4-2h3V2H6v8zm-4 4h3V2H2v12zm-1 1h13V1H1v14zM14 0H1a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h13a1 1 0 0 0 1-1V1a1 1 0 0 0-1-1z"/></svg>
    Projects
    <span class="counter">0</span>
</a>


  <a href="/cpu/boulder/pulse" class="js-selected-navigation-item reponav-item" data-selected-links="pulse /cpu/boulder/pulse">
    <svg aria-hidden="true" class="octicon octicon-pulse" height="16" version="1.1" viewBox="0 0 14 16" width="14"><path fill-rule="evenodd" d="M11.5 8L8.8 5.4 6.6 8.5 5.5 1.6 2.38 8H0v2h3.6l.9-1.8.9 5.4L9 8.5l1.6 1.5H14V8z"/></svg>
    Pulse
</a>
  <a href="/cpu/boulder/graphs" class="js-selected-navigation-item reponav-item" data-selected-links="repo_graphs repo_contributors /cpu/boulder/graphs">
    <svg aria-hidden="true" class="octicon octicon-graph" height="16" version="1.1" viewBox="0 0 16 16" width="16"><path fill-rule="evenodd" d="M16 14v1H0V0h1v14h15zM5 13H3V8h2v5zm4 0H7V3h2v10zm4 0h-2V6h2v7z"/></svg>
    Graphs
</a>

</nav>

  </div>
</div>

<div class="container new-discussion-timeline experiment-repo-nav">
  <div class="repository-content">

    

<a href="/cpu/boulder/blob/3dcf4de4b4a42f227df61dff562d5f5958cfa85a/test/gsb-test-srv/proto/safebrowsing.pb.go" class="d-none js-permalink-shortcut" data-hotkey="y">Permalink</a>

<!-- blob contrib key: blob_contributors:v21:ce6def7435d0cd37ada97d0d808e6ed0 -->

<div class="file-navigation js-zeroclipboard-container">
  
<div class="select-menu branch-select-menu js-menu-container js-select-menu float-left">
  <button class="btn btn-sm select-menu-button js-menu-target css-truncate" data-hotkey="w"
    
    type="button" aria-label="Switch branches or tags" tabindex="0" aria-haspopup="true">
    <i>Tree:</i>
    <span class="js-select-button css-truncate-target">3dcf4de4b4</span>
  </button>

  <div class="select-menu-modal-holder js-menu-content js-navigation-container" data-pjax aria-hidden="true">

    <div class="select-menu-modal">
      <div class="select-menu-header">
        <svg aria-label="Close" class="octicon octicon-x js-menu-close" height="16" role="img" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M7.48 8l3.75 3.75-1.48 1.48L6 9.48l-3.75 3.75-1.48-1.48L4.52 8 .77 4.25l1.48-1.48L6 6.52l3.75-3.75 1.48 1.48z"/></svg>
        <span class="select-menu-title">Switch branches/tags</span>
      </div>

      <div class="select-menu-filters">
        <div class="select-menu-text-filter">
          <input type="text" aria-label="Filter branches/tags" id="context-commitish-filter-field" class="form-control js-filterable-field js-navigation-enable" placeholder="Filter branches/tags">
        </div>
        <div class="select-menu-tabs">
          <ul>
            <li class="select-menu-tab">
              <a href="#" data-tab-filter="branches" data-filter-placeholder="Filter branches/tags" class="js-select-menu-tab" role="tab">Branches</a>
            </li>
            <li class="select-menu-tab">
              <a href="#" data-tab-filter="tags" data-filter-placeholder="Find a tag…" class="js-select-menu-tab" role="tab">Tags</a>
            </li>
          </ul>
        </div>
      </div>

      <div class="select-menu-list select-menu-tab-bucket js-select-menu-tab-bucket" data-tab-filter="branches" role="menu">

        <div data-filterable-for="context-commitish-filter-field" data-filterable-type="substring">


            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/441-vet_int64/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="441-vet_int64"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                441-vet_int64
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/add-caa-tools/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="add-caa-tools"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                add-caa-tools
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/add-grpc/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="add-grpc"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                add-grpc
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/audit-err/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="audit-err"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                audit-err
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/authz-purger/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="authz-purger"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                authz-purger
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/authz-ratelimit/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="authz-ratelimit"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                authz-ratelimit
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/authz-redirect/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="authz-redirect"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                authz-redirect
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/authz404/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="authz404"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                authz404
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/autoincrement/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="autoincrement"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                autoincrement
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/better-errors/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="better-errors"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                better-errors
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/build_id/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="build_id"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                build_id
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/ca-bench/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="ca-bench"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                ca-bench
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/ca-clean/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="ca-clean"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                ca-clean
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/caa-quorum/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="caa-quorum"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                caa-quorum
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/cdr-race/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="cdr-race"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                cdr-race
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/certificate_not_null_travis/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="certificate_not_null_travis"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                certificate_not_null_travis
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/challenge-updates/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="challenge-updates"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                challenge-updates
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/challenges_not_null/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="challenges_not_null"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                challenges_not_null
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/clarify-email/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="clarify-email"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                clarify-email
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/cmd-consolidation/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="cmd-consolidation"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                cmd-consolidation
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/cn_work/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="cn_work"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                cn_work
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/config-pkg/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="config-pkg"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                config-pkg
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/containerize/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="containerize"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                containerize
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/count-valid/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="count-valid"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                count-valid
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/coyote/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="coyote"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                coyote
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/cpu-2097-repro/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="cpu-2097-repro"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                cpu-2097-repro
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/cpu-contact-exporter/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="cpu-contact-exporter"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                cpu-contact-exporter
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/cpu-ess-emm-tee-pee-plus/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="cpu-ess-emm-tee-pee-plus"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                cpu-ess-emm-tee-pee-plus
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/cpu-fresh-selecta/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="cpu-fresh-selecta"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                cpu-fresh-selecta
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/cpu-mock-gsb/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="cpu-mock-gsb"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                cpu-mock-gsb
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/cpu-one-authz-to-rule-them-all/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="cpu-one-authz-to-rule-them-all"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                cpu-one-authz-to-rule-them-all
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/cpu-readme-chall-ports/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="cpu-readme-chall-ports"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                cpu-readme-chall-ports
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/csr-checking/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="csr-checking"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                csr-checking
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/ct-2/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="ct-2"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                ct-2
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/ct-ocsp/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="ct-ocsp"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                ct-ocsp
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/ct-sig/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="ct-sig"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                ct-sig
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/ct-submission-verified/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="ct-submission-verified"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                ct-submission-verified
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/deb-weak-keys/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="deb-weak-keys"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                deb-weak-keys
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/der_field_smaller/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="der_field_smaller"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                der_field_smaller
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/docker-build/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="docker-build"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                docker-build
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/dvsni2/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="dvsni2"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                dvsni2
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/empty-ocsp/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="empty-ocsp"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                empty-ocsp
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/empty-sct/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="empty-sct"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                empty-sct
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/error-wording/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="error-wording"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                error-wording
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/exact-blacklist/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="exact-blacklist"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                exact-blacklist
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/exempt-fqdn-cbn/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="exempt-fqdn-cbn"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                exempt-fqdn-cbn
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/feature-flags/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="feature-flags"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                feature-flags
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/fix-aaaa-race/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="fix-aaaa-race"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                fix-aaaa-race
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/fix-cdr/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="fix-cdr"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                fix-cdr
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/fix-ocsp-integration-test/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="fix-ocsp-integration-test"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                fix-ocsp-integration-test
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/go-generate-test/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="go-generate-test"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                go-generate-test
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/go1.6-test/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="go1.6-test"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                go1.6-test
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/go1.6/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="go1.6"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                go1.6
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/grpc-metric-gen/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="grpc-metric-gen"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                grpc-metric-gen
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/grpc-va-2/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="grpc-va-2"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                grpc-va-2
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/happy-eyeballs/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="happy-eyeballs"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                happy-eyeballs
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/hsm-down/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="hsm-down"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                hsm-down
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/hsm-fault-ocsp-backoff/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="hsm-fault-ocsp-backoff"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                hsm-fault-ocsp-backoff
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/integration/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="integration"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                integration
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/investigate-containers/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="investigate-containers"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                investigate-containers
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/ipv6/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="ipv6"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                ipv6
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/issued-names/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="issued-names"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                issued-names
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/issuerconfig-ca2/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="issuerconfig-ca2"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                issuerconfig-ca2
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/issuerconfig/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="issuerconfig"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                issuerconfig
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/jcj/master/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="jcj/master"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                jcj/master
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/keyrotate/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="keyrotate"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                keyrotate
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/le_dns/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="le_dns"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                le_dns
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/le_failure/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="le_failure"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                le_failure
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/load-generators/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="load-generators"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                load-generators
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/loadtest_stats/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="loadtest_stats"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                loadtest_stats
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/local-protoc-gen-go/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="local-protoc-gen-go"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                local-protoc-gen-go
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/log-less/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="log-less"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                log-less
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/lowercase-policy/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="lowercase-policy"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                lowercase-policy
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/mac-recovery/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="mac-recovery"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                mac-recovery
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/mailer-re-re-reconnect/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="mailer-re-re-reconnect"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                mailer-re-re-reconnect
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/marshalindent/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="marshalindent"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                marshalindent
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/master/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="master"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                master
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/misc-fixes-2015-10-12/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="misc-fixes-2015-10-12"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                misc-fixes-2015-10-12
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/more-stats/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="more-stats"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                more-stats
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/multi-ra-email/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="multi-ra-email"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                multi-ra-email
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/mysql-conn-stats/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="mysql-conn-stats"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                mysql-conn-stats
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/new-reviews/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="new-reviews"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                new-reviews
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/no-check-ocspresponses/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="no-check-ocspresponses"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                no-check-ocspresponses
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/no-ignore-errors/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="no-ignore-errors"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                no-ignore-errors
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/notify-mailer/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="notify-mailer"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                notify-mailer
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/paranoid-key-storage/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="paranoid-key-storage"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                paranoid-key-storage
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/pass-log/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="pass-log"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                pass-log
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/permissions2/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="permissions2"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                permissions2
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/policy-checks/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="policy-checks"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                policy-checks
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/problemdetails-passthrough/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="problemdetails-passthrough"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                problemdetails-passthrough
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/prod_with_pkcs11/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="prod_with_pkcs11"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                prod_with_pkcs11
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/psl-gen/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="psl-gen"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                psl-gen
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/ra-success-stat/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="ra-success-stat"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                ra-success-stat
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/ra-test-fix-must-staple/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="ra-test-fix-must-staple"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                ra-test-fix-must-staple
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/ra-test-fix/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="ra-test-fix"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                ra-test-fix
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/race/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="race"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                race
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/rate-limit-reloader/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="rate-limit-reloader"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                rate-limit-reloader
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/reduce_jwk_storage/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="reduce_jwk_storage"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                reduce_jwk_storage
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/reg-rate-limit-3/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="reg-rate-limit-3"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                reg-rate-limit-3
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/release/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="release"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                release
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/remove-insecure-challenges/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="remove-insecure-challenges"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                remove-insecure-challenges
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/remove_travis_host/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="remove_travis_host"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                remove_travis_host
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/restore-godep-test/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="restore-godep-test"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                restore-godep-test
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/rm-set-auditlogger/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="rm-set-auditlogger"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                rm-set-auditlogger
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/rpc-maxgoroutines/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="rpc-maxgoroutines"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                rpc-maxgoroutines
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/serial_unique_index/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="serial_unique_index"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                serial_unique_index
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/sig-verify/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="sig-verify"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                sig-verify
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/staging/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="staging"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                staging
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/stop-offering/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="stop-offering"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                stop-offering
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/switch-gojose/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="switch-gojose"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                switch-gojose
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/tasty-databass-one/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="tasty-databass-one"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                tasty-databass-one
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-1-cpu-master-ct-verify/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-1-cpu-master-ct-verify"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-1-cpu-master-ct-verify
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-1/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-1"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-1
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-2-cpu-master-ct-verify/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-2-cpu-master-ct-verify"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-2-cpu-master-ct-verify
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-2/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-2"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-2
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-3-cpu-master-ct-verify/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-3-cpu-master-ct-verify"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-3-cpu-master-ct-verify
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-3/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-3"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-3
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-4-cpu-master-ct-verify/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-4-cpu-master-ct-verify"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-4-cpu-master-ct-verify
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-4/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-4"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-4
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-5-cpu-master-ct-verify/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-5-cpu-master-ct-verify"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-5-cpu-master-ct-verify
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-5/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-5"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-5
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-6-cpu-master-ct-verify/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-6-cpu-master-ct-verify"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-6-cpu-master-ct-verify
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-6/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-6"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-6
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-7-cpu-master-ct-verify/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-7-cpu-master-ct-verify"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-7-cpu-master-ct-verify
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-7/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-7"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-7
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-8-cpu-master-ct-verify/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-8-cpu-master-ct-verify"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-8-cpu-master-ct-verify
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-8/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-8"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-8
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-9-cpu-master-ct-verify/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-9-cpu-master-ct-verify"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-9-cpu-master-ct-verify
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-9/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-9"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-9
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-10-cpu-master-ct-verify/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-10-cpu-master-ct-verify"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-10-cpu-master-ct-verify
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-10/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-10"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-10
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-amqp-rpc-timeout-1/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-amqp-rpc-timeout-1"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-amqp-rpc-timeout-1
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-amqp-rpc-timeout-2/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-amqp-rpc-timeout-2"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-amqp-rpc-timeout-2
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-amqp-rpc-timeout-3/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-amqp-rpc-timeout-3"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-amqp-rpc-timeout-3
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-cpu-missing-scts-reward-if-found-1/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-cpu-missing-scts-reward-if-found-1"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-cpu-missing-scts-reward-if-found-1
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-cpu-missing-scts-reward-if-found-2/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-cpu-missing-scts-reward-if-found-2"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-cpu-missing-scts-reward-if-found-2
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-cpu-missing-scts-reward-if-found-3/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-cpu-missing-scts-reward-if-found-3"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-cpu-missing-scts-reward-if-found-3
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-cpu-missing-scts-reward-if-found-4/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-cpu-missing-scts-reward-if-found-4"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-cpu-missing-scts-reward-if-found-4
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-cpu-missing-scts-reward-if-found-5/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-cpu-missing-scts-reward-if-found-5"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-cpu-missing-scts-reward-if-found-5
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-cpu-missing-scts-reward-if-found-6/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-cpu-missing-scts-reward-if-found-6"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-cpu-missing-scts-reward-if-found-6
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-cpu-missing-scts-reward-if-found-7/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-cpu-missing-scts-reward-if-found-7"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-cpu-missing-scts-reward-if-found-7
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-cpu-missing-scts-reward-if-found-8/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-cpu-missing-scts-reward-if-found-8"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-cpu-missing-scts-reward-if-found-8
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-cpu-missing-scts-reward-if-found-9/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-cpu-missing-scts-reward-if-found-9"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-cpu-missing-scts-reward-if-found-9
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-cpu-missing-scts-reward-if-found-10/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-cpu-missing-scts-reward-if-found-10"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-cpu-missing-scts-reward-if-found-10
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-cpu-missing-scts-reward-if-found/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-cpu-missing-scts-reward-if-found"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-cpu-missing-scts-reward-if-found
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-docker-maria101/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-docker-maria101"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-docker-maria101
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-go1.6/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-go1.6"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-go1.6
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-godep-restore/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-godep-restore"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-godep-restore
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-godep-simpler/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-godep-simpler"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-godep-simpler
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-integration-quiet/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-integration-quiet"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-integration-quiet
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-mariadb-failure-2/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-mariadb-failure-2"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-mariadb-failure-2
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-master-1/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-master-1"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-master-1
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-master-2/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-master-2"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-master-2
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-master-3/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-master-3"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-master-3
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-master-4/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-master-4"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-master-4
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-master-5/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-master-5"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-master-5
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-master-6/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-master-6"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-master-6
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-master-7/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-master-7"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-master-7
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-master-8/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-master-8"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-master-8
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-master-9/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-master-9"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-master-9
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-master-10/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-master-10"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-master-10
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-notify-mailer/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-notify-mailer"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-notify-mailer
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-rate-limit-reloader/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-rate-limit-reloader"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-rate-limit-reloader
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-remove-deps/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-remove-deps"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-remove-deps
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-sct-branch/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-sct-branch"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-sct-branch
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-travis-cmds/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-travis-cmds"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-travis-cmds
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/test-vendorvendorvendor2/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="test-vendorvendorvendor2"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                test-vendorvendorvendor2
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/tor-va/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="tor-va"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                tor-va
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/unsub/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="unsub"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                unsub
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/update-cfssl/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="update-cfssl"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                update-cfssl
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/update-docs/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="update-docs"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                update-docs
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/va-grpc/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="va-grpc"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                va-grpc
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/validate-simplehttp-key/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="validate-simplehttp-key"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                validate-simplehttp-key
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/cpu/boulder/blob/vendorvendorvendor/test/gsb-test-srv/proto/safebrowsing.pb.go"
               data-name="vendorvendorvendor"
               data-skip-pjax="true"
               rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target js-select-menu-filter-text">
                vendorvendorvendor
              </span>
            </a>
        </div>

          <div class="select-menu-no-results">Nothing to show</div>
      </div>

      <div class="select-menu-list select-menu-tab-bucket js-select-menu-tab-bucket" data-tab-filter="tags">
        <div data-filterable-for="context-commitish-filter-field" data-filterable-type="substring">


            <a class="select-menu-item js-navigation-item js-navigation-open "
              href="/cpu/boulder/tree/release-2015-12-07/test/gsb-test-srv/proto/safebrowsing.pb.go"
              data-name="release-2015-12-07"
              data-skip-pjax="true"
              rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target" title="release-2015-12-07">
                release-2015-12-07
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
              href="/cpu/boulder/tree/ncc-audit-20150601/test/gsb-test-srv/proto/safebrowsing.pb.go"
              data-name="ncc-audit-20150601"
              data-skip-pjax="true"
              rel="nofollow">
              <svg aria-hidden="true" class="octicon octicon-check select-menu-item-icon" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M12 5l-8 8-4-4 1.5-1.5L4 10l6.5-6.5z"/></svg>
              <span class="select-menu-item-text css-truncate-target" title="ncc-audit-20150601">
                ncc-audit-20150601
              </span>
            </a>
        </div>

        <div class="select-menu-no-results">Nothing to show</div>
      </div>

    </div>
  </div>
</div>

  <div class="BtnGroup float-right">
    <a href="/cpu/boulder/find/3dcf4de4b4a42f227df61dff562d5f5958cfa85a"
          class="js-pjax-capture-input btn btn-sm BtnGroup-item"
          data-pjax
          data-hotkey="t">
      Find file
    </a>
    <button aria-label="Copy file path to clipboard" class="js-zeroclipboard btn btn-sm BtnGroup-item tooltipped tooltipped-s" data-copied-hint="Copied!" type="button">Copy path</button>
  </div>
  <div class="breadcrumb js-zeroclipboard-target">
    <span class="repo-root js-repo-root"><span class="js-path-segment"><a href="/cpu/boulder/tree/3dcf4de4b4a42f227df61dff562d5f5958cfa85a"><span>boulder</span></a></span></span><span class="separator">/</span><span class="js-path-segment"><a href="/cpu/boulder/tree/3dcf4de4b4a42f227df61dff562d5f5958cfa85a/test"><span>test</span></a></span><span class="separator">/</span><span class="js-path-segment"><a href="/cpu/boulder/tree/3dcf4de4b4a42f227df61dff562d5f5958cfa85a/test/gsb-test-srv"><span>gsb-test-srv</span></a></span><span class="separator">/</span><span class="js-path-segment"><a href="/cpu/boulder/tree/3dcf4de4b4a42f227df61dff562d5f5958cfa85a/test/gsb-test-srv/proto"><span>proto</span></a></span><span class="separator">/</span><strong class="final-path">safebrowsing.pb.go</strong>
  </div>
</div>


  <div class="commit-tease">
      <span class="float-right">
        <a class="commit-tease-sha" href="/cpu/boulder/commit/63c9f74a1064e03bb87a9bedb05285700cbc03d8" data-pjax>
          63c9f74
        </a>
        <relative-time datetime="2017-01-11T19:21:47Z">Jan 11, 2017</relative-time>
      </span>
      <div>
        <img alt="@cpu" class="avatar" height="20" src="https://avatars0.githubusercontent.com/u/292650?v=3&amp;s=40" width="20" />
        <a href="/cpu" class="user-mention" rel="author">cpu</a>
          <a href="/cpu/boulder/commit/63c9f74a1064e03bb87a9bedb05285700cbc03d8" class="message" data-pjax="true" title="WIP - test google safe browsing server">WIP - test google safe browsing server</a>
      </div>

    <div class="commit-tease-contributors">
      <button type="button" class="btn-link muted-link contributors-toggle" data-facebox="#blob_contributors_box">
        <strong>1</strong>
         contributor
      </button>
      
    </div>

    <div id="blob_contributors_box" style="display:none">
      <h2 class="facebox-header" data-facebox-id="facebox-header">Users who have contributed to this file</h2>
      <ul class="facebox-user-list" data-facebox-id="facebox-description">
          <li class="facebox-user-list-item">
            <img alt="@cpu" height="24" src="https://avatars2.githubusercontent.com/u/292650?v=3&amp;s=48" width="24" />
            <a href="/cpu">cpu</a>
          </li>
      </ul>
    </div>
  </div>


<div class="file">
  <div class="file-header">
  <div class="file-actions">

    <div class="BtnGroup">
      <a href="/cpu/boulder/raw/3dcf4de4b4a42f227df61dff562d5f5958cfa85a/test/gsb-test-srv/proto/safebrowsing.pb.go" class="btn btn-sm BtnGroup-item" id="raw-url">Raw</a>
        <a href="/cpu/boulder/blame/3dcf4de4b4a42f227df61dff562d5f5958cfa85a/test/gsb-test-srv/proto/safebrowsing.pb.go" class="btn btn-sm js-update-url-with-hash BtnGroup-item">Blame</a>
      <a href="/cpu/boulder/commits/3dcf4de4b4a42f227df61dff562d5f5958cfa85a/test/gsb-test-srv/proto/safebrowsing.pb.go" class="btn btn-sm BtnGroup-item" rel="nofollow">History</a>
    </div>


        <button type="button" class="btn-octicon disabled tooltipped tooltipped-nw"
          aria-label="You must be signed in to make or propose changes">
          <svg aria-hidden="true" class="octicon octicon-pencil" height="16" version="1.1" viewBox="0 0 14 16" width="14"><path fill-rule="evenodd" d="M0 12v3h3l8-8-3-3-8 8zm3 2H1v-2h1v1h1v1zm10.3-9.3L12 6 9 3l1.3-1.3a.996.996 0 0 1 1.41 0l1.59 1.59c.39.39.39 1.02 0 1.41z"/></svg>
        </button>
        <button type="button" class="btn-octicon btn-octicon-danger disabled tooltipped tooltipped-nw"
          aria-label="You must be signed in to make or propose changes">
          <svg aria-hidden="true" class="octicon octicon-trashcan" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M11 2H9c0-.55-.45-1-1-1H5c-.55 0-1 .45-1 1H2c-.55 0-1 .45-1 1v1c0 .55.45 1 1 1v9c0 .55.45 1 1 1h7c.55 0 1-.45 1-1V5c.55 0 1-.45 1-1V3c0-.55-.45-1-1-1zm-1 12H3V5h1v8h1V5h1v8h1V5h1v8h1V5h1v9zm1-10H2V3h9v1z"/></svg>
        </button>
  </div>

  <div class="file-info">
      967 lines (865 sloc)
      <span class="file-info-divider"></span>
    47.3 KB
  </div>
</div>

  

  <div itemprop="text" class="blob-wrapper data type-go">
      <table class="highlight tab-size js-file-line-container" data-tab-size="8">
      <tr>
        <td id="L1" class="blob-num js-line-number" data-line-number="1"></td>
        <td id="LC1" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> Code generated by protoc-gen-go.</span></td>
      </tr>
      <tr>
        <td id="L2" class="blob-num js-line-number" data-line-number="2"></td>
        <td id="LC2" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> source: safebrowsing.proto</span></td>
      </tr>
      <tr>
        <td id="L3" class="blob-num js-line-number" data-line-number="3"></td>
        <td id="LC3" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> DO NOT EDIT!</span></td>
      </tr>
      <tr>
        <td id="L4" class="blob-num js-line-number" data-line-number="4"></td>
        <td id="LC4" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L5" class="blob-num js-line-number" data-line-number="5"></td>
        <td id="LC5" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">/*</span></span></td>
      </tr>
      <tr>
        <td id="L6" class="blob-num js-line-number" data-line-number="6"></td>
        <td id="LC6" class="blob-code blob-code-inner js-file-line"><span class="pl-c">Package safebrowsing_proto is a generated protocol buffer package.</span></td>
      </tr>
      <tr>
        <td id="L7" class="blob-num js-line-number" data-line-number="7"></td>
        <td id="LC7" class="blob-code blob-code-inner js-file-line"><span class="pl-c"></span></td>
      </tr>
      <tr>
        <td id="L8" class="blob-num js-line-number" data-line-number="8"></td>
        <td id="LC8" class="blob-code blob-code-inner js-file-line"><span class="pl-c">It is generated from these files:</span></td>
      </tr>
      <tr>
        <td id="L9" class="blob-num js-line-number" data-line-number="9"></td>
        <td id="LC9" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	safebrowsing.proto</span></td>
      </tr>
      <tr>
        <td id="L10" class="blob-num js-line-number" data-line-number="10"></td>
        <td id="LC10" class="blob-code blob-code-inner js-file-line"><span class="pl-c"></span></td>
      </tr>
      <tr>
        <td id="L11" class="blob-num js-line-number" data-line-number="11"></td>
        <td id="LC11" class="blob-code blob-code-inner js-file-line"><span class="pl-c">It has these top-level messages:</span></td>
      </tr>
      <tr>
        <td id="L12" class="blob-num js-line-number" data-line-number="12"></td>
        <td id="LC12" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	ThreatInfo</span></td>
      </tr>
      <tr>
        <td id="L13" class="blob-num js-line-number" data-line-number="13"></td>
        <td id="LC13" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	ThreatMatch</span></td>
      </tr>
      <tr>
        <td id="L14" class="blob-num js-line-number" data-line-number="14"></td>
        <td id="LC14" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	FindThreatMatchesRequest</span></td>
      </tr>
      <tr>
        <td id="L15" class="blob-num js-line-number" data-line-number="15"></td>
        <td id="LC15" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	FindThreatMatchesResponse</span></td>
      </tr>
      <tr>
        <td id="L16" class="blob-num js-line-number" data-line-number="16"></td>
        <td id="LC16" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	FetchThreatListUpdatesRequest</span></td>
      </tr>
      <tr>
        <td id="L17" class="blob-num js-line-number" data-line-number="17"></td>
        <td id="LC17" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	FetchThreatListUpdatesResponse</span></td>
      </tr>
      <tr>
        <td id="L18" class="blob-num js-line-number" data-line-number="18"></td>
        <td id="LC18" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	FindFullHashesRequest</span></td>
      </tr>
      <tr>
        <td id="L19" class="blob-num js-line-number" data-line-number="19"></td>
        <td id="LC19" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	FindFullHashesResponse</span></td>
      </tr>
      <tr>
        <td id="L20" class="blob-num js-line-number" data-line-number="20"></td>
        <td id="LC20" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	ClientInfo</span></td>
      </tr>
      <tr>
        <td id="L21" class="blob-num js-line-number" data-line-number="21"></td>
        <td id="LC21" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	Checksum</span></td>
      </tr>
      <tr>
        <td id="L22" class="blob-num js-line-number" data-line-number="22"></td>
        <td id="LC22" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	ThreatEntry</span></td>
      </tr>
      <tr>
        <td id="L23" class="blob-num js-line-number" data-line-number="23"></td>
        <td id="LC23" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	ThreatEntrySet</span></td>
      </tr>
      <tr>
        <td id="L24" class="blob-num js-line-number" data-line-number="24"></td>
        <td id="LC24" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	RawIndices</span></td>
      </tr>
      <tr>
        <td id="L25" class="blob-num js-line-number" data-line-number="25"></td>
        <td id="LC25" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	RawHashes</span></td>
      </tr>
      <tr>
        <td id="L26" class="blob-num js-line-number" data-line-number="26"></td>
        <td id="LC26" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	RiceDeltaEncoding</span></td>
      </tr>
      <tr>
        <td id="L27" class="blob-num js-line-number" data-line-number="27"></td>
        <td id="LC27" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	ThreatEntryMetadata</span></td>
      </tr>
      <tr>
        <td id="L28" class="blob-num js-line-number" data-line-number="28"></td>
        <td id="LC28" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	ThreatListDescriptor</span></td>
      </tr>
      <tr>
        <td id="L29" class="blob-num js-line-number" data-line-number="29"></td>
        <td id="LC29" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	ListThreatListsResponse</span></td>
      </tr>
      <tr>
        <td id="L30" class="blob-num js-line-number" data-line-number="30"></td>
        <td id="LC30" class="blob-code blob-code-inner js-file-line"><span class="pl-c">	Duration</span></td>
      </tr>
      <tr>
        <td id="L31" class="blob-num js-line-number" data-line-number="31"></td>
        <td id="LC31" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">*/</span></span></td>
      </tr>
      <tr>
        <td id="L32" class="blob-num js-line-number" data-line-number="32"></td>
        <td id="LC32" class="blob-code blob-code-inner js-file-line"><span class="pl-k">package</span> safebrowsing_proto</td>
      </tr>
      <tr>
        <td id="L33" class="blob-num js-line-number" data-line-number="33"></td>
        <td id="LC33" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L34" class="blob-num js-line-number" data-line-number="34"></td>
        <td id="LC34" class="blob-code blob-code-inner js-file-line"><span class="pl-k">import</span> proto <span class="pl-s"><span class="pl-pds">&quot;</span>github.com/golang/protobuf/proto<span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L35" class="blob-num js-line-number" data-line-number="35"></td>
        <td id="LC35" class="blob-code blob-code-inner js-file-line"><span class="pl-k">import</span> fmt <span class="pl-s"><span class="pl-pds">&quot;</span>fmt<span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L36" class="blob-num js-line-number" data-line-number="36"></td>
        <td id="LC36" class="blob-code blob-code-inner js-file-line"><span class="pl-k">import</span> math <span class="pl-s"><span class="pl-pds">&quot;</span>math<span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L37" class="blob-num js-line-number" data-line-number="37"></td>
        <td id="LC37" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L38" class="blob-num js-line-number" data-line-number="38"></td>
        <td id="LC38" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> Reference imports to suppress errors if they are not otherwise used.</span></td>
      </tr>
      <tr>
        <td id="L39" class="blob-num js-line-number" data-line-number="39"></td>
        <td id="LC39" class="blob-code blob-code-inner js-file-line"><span class="pl-k">var</span> <span class="pl-smi">_</span> = proto.<span class="pl-smi">Marshal</span></td>
      </tr>
      <tr>
        <td id="L40" class="blob-num js-line-number" data-line-number="40"></td>
        <td id="LC40" class="blob-code blob-code-inner js-file-line"><span class="pl-k">var</span> <span class="pl-smi">_</span> = fmt.<span class="pl-smi">Errorf</span></td>
      </tr>
      <tr>
        <td id="L41" class="blob-num js-line-number" data-line-number="41"></td>
        <td id="LC41" class="blob-code blob-code-inner js-file-line"><span class="pl-k">var</span> <span class="pl-smi">_</span> = math.<span class="pl-smi">Inf</span></td>
      </tr>
      <tr>
        <td id="L42" class="blob-num js-line-number" data-line-number="42"></td>
        <td id="LC42" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L43" class="blob-num js-line-number" data-line-number="43"></td>
        <td id="LC43" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> This is a compile-time assertion to ensure that this generated file</span></td>
      </tr>
      <tr>
        <td id="L44" class="blob-num js-line-number" data-line-number="44"></td>
        <td id="LC44" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> is compatible with the proto package it is being compiled against.</span></td>
      </tr>
      <tr>
        <td id="L45" class="blob-num js-line-number" data-line-number="45"></td>
        <td id="LC45" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> A compilation error at this line likely means your copy of the</span></td>
      </tr>
      <tr>
        <td id="L46" class="blob-num js-line-number" data-line-number="46"></td>
        <td id="LC46" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> proto package needs to be updated.</span></td>
      </tr>
      <tr>
        <td id="L47" class="blob-num js-line-number" data-line-number="47"></td>
        <td id="LC47" class="blob-code blob-code-inner js-file-line"><span class="pl-k">const</span> _ = proto.<span class="pl-smi">ProtoPackageIsVersion2</span> <span class="pl-c"><span class="pl-c">//</span> please upgrade the proto package</span></td>
      </tr>
      <tr>
        <td id="L48" class="blob-num js-line-number" data-line-number="48"></td>
        <td id="LC48" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L49" class="blob-num js-line-number" data-line-number="49"></td>
        <td id="LC49" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> Types of threats.</span></td>
      </tr>
      <tr>
        <td id="L50" class="blob-num js-line-number" data-line-number="50"></td>
        <td id="LC50" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">ThreatType</span> <span class="pl-k">int32</span></td>
      </tr>
      <tr>
        <td id="L51" class="blob-num js-line-number" data-line-number="51"></td>
        <td id="LC51" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L52" class="blob-num js-line-number" data-line-number="52"></td>
        <td id="LC52" class="blob-code blob-code-inner js-file-line"><span class="pl-k">const</span> (</td>
      </tr>
      <tr>
        <td id="L53" class="blob-num js-line-number" data-line-number="53"></td>
        <td id="LC53" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Unknown.</span></td>
      </tr>
      <tr>
        <td id="L54" class="blob-num js-line-number" data-line-number="54"></td>
        <td id="LC54" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatType_THREAT_TYPE_UNSPECIFIED</span> <span class="pl-v">ThreatType</span> = <span class="pl-c1">0</span></td>
      </tr>
      <tr>
        <td id="L55" class="blob-num js-line-number" data-line-number="55"></td>
        <td id="LC55" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Malware threat type.</span></td>
      </tr>
      <tr>
        <td id="L56" class="blob-num js-line-number" data-line-number="56"></td>
        <td id="LC56" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatType_MALWARE</span> <span class="pl-v">ThreatType</span> = <span class="pl-c1">1</span></td>
      </tr>
      <tr>
        <td id="L57" class="blob-num js-line-number" data-line-number="57"></td>
        <td id="LC57" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Social engineering threat type.</span></td>
      </tr>
      <tr>
        <td id="L58" class="blob-num js-line-number" data-line-number="58"></td>
        <td id="LC58" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatType_SOCIAL_ENGINEERING</span> <span class="pl-v">ThreatType</span> = <span class="pl-c1">2</span></td>
      </tr>
      <tr>
        <td id="L59" class="blob-num js-line-number" data-line-number="59"></td>
        <td id="LC59" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Unwanted software threat type.</span></td>
      </tr>
      <tr>
        <td id="L60" class="blob-num js-line-number" data-line-number="60"></td>
        <td id="LC60" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatType_UNWANTED_SOFTWARE</span> <span class="pl-v">ThreatType</span> = <span class="pl-c1">3</span></td>
      </tr>
      <tr>
        <td id="L61" class="blob-num js-line-number" data-line-number="61"></td>
        <td id="LC61" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Potentially harmful application threat type.</span></td>
      </tr>
      <tr>
        <td id="L62" class="blob-num js-line-number" data-line-number="62"></td>
        <td id="LC62" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatType_POTENTIALLY_HARMFUL_APPLICATION</span> <span class="pl-v">ThreatType</span> = <span class="pl-c1">4</span></td>
      </tr>
      <tr>
        <td id="L63" class="blob-num js-line-number" data-line-number="63"></td>
        <td id="LC63" class="blob-code blob-code-inner js-file-line">)</td>
      </tr>
      <tr>
        <td id="L64" class="blob-num js-line-number" data-line-number="64"></td>
        <td id="LC64" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L65" class="blob-num js-line-number" data-line-number="65"></td>
        <td id="LC65" class="blob-code blob-code-inner js-file-line"><span class="pl-k">var</span> <span class="pl-smi">ThreatType_name</span> = <span class="pl-k">map</span>[<span class="pl-k">int32</span>]<span class="pl-k">string</span>{</td>
      </tr>
      <tr>
        <td id="L66" class="blob-num js-line-number" data-line-number="66"></td>
        <td id="LC66" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>THREAT_TYPE_UNSPECIFIED<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L67" class="blob-num js-line-number" data-line-number="67"></td>
        <td id="LC67" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">1</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>MALWARE<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L68" class="blob-num js-line-number" data-line-number="68"></td>
        <td id="LC68" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">2</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>SOCIAL_ENGINEERING<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L69" class="blob-num js-line-number" data-line-number="69"></td>
        <td id="LC69" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">3</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>UNWANTED_SOFTWARE<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L70" class="blob-num js-line-number" data-line-number="70"></td>
        <td id="LC70" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">4</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>POTENTIALLY_HARMFUL_APPLICATION<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L71" class="blob-num js-line-number" data-line-number="71"></td>
        <td id="LC71" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L72" class="blob-num js-line-number" data-line-number="72"></td>
        <td id="LC72" class="blob-code blob-code-inner js-file-line"><span class="pl-k">var</span> <span class="pl-smi">ThreatType_value</span> = <span class="pl-k">map</span>[<span class="pl-k">string</span>]<span class="pl-k">int32</span>{</td>
      </tr>
      <tr>
        <td id="L73" class="blob-num js-line-number" data-line-number="73"></td>
        <td id="LC73" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>THREAT_TYPE_UNSPECIFIED<span class="pl-pds">&quot;</span></span>:         <span class="pl-c1">0</span>,</td>
      </tr>
      <tr>
        <td id="L74" class="blob-num js-line-number" data-line-number="74"></td>
        <td id="LC74" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>MALWARE<span class="pl-pds">&quot;</span></span>:                         <span class="pl-c1">1</span>,</td>
      </tr>
      <tr>
        <td id="L75" class="blob-num js-line-number" data-line-number="75"></td>
        <td id="LC75" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>SOCIAL_ENGINEERING<span class="pl-pds">&quot;</span></span>:              <span class="pl-c1">2</span>,</td>
      </tr>
      <tr>
        <td id="L76" class="blob-num js-line-number" data-line-number="76"></td>
        <td id="LC76" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>UNWANTED_SOFTWARE<span class="pl-pds">&quot;</span></span>:               <span class="pl-c1">3</span>,</td>
      </tr>
      <tr>
        <td id="L77" class="blob-num js-line-number" data-line-number="77"></td>
        <td id="LC77" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>POTENTIALLY_HARMFUL_APPLICATION<span class="pl-pds">&quot;</span></span>: <span class="pl-c1">4</span>,</td>
      </tr>
      <tr>
        <td id="L78" class="blob-num js-line-number" data-line-number="78"></td>
        <td id="LC78" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L79" class="blob-num js-line-number" data-line-number="79"></td>
        <td id="LC79" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L80" class="blob-num js-line-number" data-line-number="80"></td>
        <td id="LC80" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">x</span> <span class="pl-v">ThreatType</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span> {</td>
      </tr>
      <tr>
        <td id="L81" class="blob-num js-line-number" data-line-number="81"></td>
        <td id="LC81" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> proto.<span class="pl-c1">EnumName</span>(ThreatType_name, <span class="pl-c1">int32</span>(x))</td>
      </tr>
      <tr>
        <td id="L82" class="blob-num js-line-number" data-line-number="82"></td>
        <td id="LC82" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L83" class="blob-num js-line-number" data-line-number="83"></td>
        <td id="LC83" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">ThreatType</span>) <span class="pl-en">EnumDescriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">0</span>} }</td>
      </tr>
      <tr>
        <td id="L84" class="blob-num js-line-number" data-line-number="84"></td>
        <td id="LC84" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L85" class="blob-num js-line-number" data-line-number="85"></td>
        <td id="LC85" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> Types of platforms.</span></td>
      </tr>
      <tr>
        <td id="L86" class="blob-num js-line-number" data-line-number="86"></td>
        <td id="LC86" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">PlatformType</span> <span class="pl-k">int32</span></td>
      </tr>
      <tr>
        <td id="L87" class="blob-num js-line-number" data-line-number="87"></td>
        <td id="LC87" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L88" class="blob-num js-line-number" data-line-number="88"></td>
        <td id="LC88" class="blob-code blob-code-inner js-file-line"><span class="pl-k">const</span> (</td>
      </tr>
      <tr>
        <td id="L89" class="blob-num js-line-number" data-line-number="89"></td>
        <td id="LC89" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Unknown platform.</span></td>
      </tr>
      <tr>
        <td id="L90" class="blob-num js-line-number" data-line-number="90"></td>
        <td id="LC90" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">PlatformType_PLATFORM_TYPE_UNSPECIFIED</span> <span class="pl-v">PlatformType</span> = <span class="pl-c1">0</span></td>
      </tr>
      <tr>
        <td id="L91" class="blob-num js-line-number" data-line-number="91"></td>
        <td id="LC91" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Threat posed to Windows.</span></td>
      </tr>
      <tr>
        <td id="L92" class="blob-num js-line-number" data-line-number="92"></td>
        <td id="LC92" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">PlatformType_WINDOWS</span> <span class="pl-v">PlatformType</span> = <span class="pl-c1">1</span></td>
      </tr>
      <tr>
        <td id="L93" class="blob-num js-line-number" data-line-number="93"></td>
        <td id="LC93" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Threat posed to Linux.</span></td>
      </tr>
      <tr>
        <td id="L94" class="blob-num js-line-number" data-line-number="94"></td>
        <td id="LC94" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">PlatformType_LINUX</span> <span class="pl-v">PlatformType</span> = <span class="pl-c1">2</span></td>
      </tr>
      <tr>
        <td id="L95" class="blob-num js-line-number" data-line-number="95"></td>
        <td id="LC95" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Threat posed to Android.</span></td>
      </tr>
      <tr>
        <td id="L96" class="blob-num js-line-number" data-line-number="96"></td>
        <td id="LC96" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">PlatformType_ANDROID</span> <span class="pl-v">PlatformType</span> = <span class="pl-c1">3</span></td>
      </tr>
      <tr>
        <td id="L97" class="blob-num js-line-number" data-line-number="97"></td>
        <td id="LC97" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Threat posed to OSX.</span></td>
      </tr>
      <tr>
        <td id="L98" class="blob-num js-line-number" data-line-number="98"></td>
        <td id="LC98" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">PlatformType_OSX</span> <span class="pl-v">PlatformType</span> = <span class="pl-c1">4</span></td>
      </tr>
      <tr>
        <td id="L99" class="blob-num js-line-number" data-line-number="99"></td>
        <td id="LC99" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Threat posed to iOS.</span></td>
      </tr>
      <tr>
        <td id="L100" class="blob-num js-line-number" data-line-number="100"></td>
        <td id="LC100" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">PlatformType_IOS</span> <span class="pl-v">PlatformType</span> = <span class="pl-c1">5</span></td>
      </tr>
      <tr>
        <td id="L101" class="blob-num js-line-number" data-line-number="101"></td>
        <td id="LC101" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Threat posed to at least one of the defined platforms.</span></td>
      </tr>
      <tr>
        <td id="L102" class="blob-num js-line-number" data-line-number="102"></td>
        <td id="LC102" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">PlatformType_ANY_PLATFORM</span> <span class="pl-v">PlatformType</span> = <span class="pl-c1">6</span></td>
      </tr>
      <tr>
        <td id="L103" class="blob-num js-line-number" data-line-number="103"></td>
        <td id="LC103" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Threat posed to all defined platforms.</span></td>
      </tr>
      <tr>
        <td id="L104" class="blob-num js-line-number" data-line-number="104"></td>
        <td id="LC104" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">PlatformType_ALL_PLATFORMS</span> <span class="pl-v">PlatformType</span> = <span class="pl-c1">7</span></td>
      </tr>
      <tr>
        <td id="L105" class="blob-num js-line-number" data-line-number="105"></td>
        <td id="LC105" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Threat posed to Chrome.</span></td>
      </tr>
      <tr>
        <td id="L106" class="blob-num js-line-number" data-line-number="106"></td>
        <td id="LC106" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">PlatformType_CHROME</span> <span class="pl-v">PlatformType</span> = <span class="pl-c1">8</span></td>
      </tr>
      <tr>
        <td id="L107" class="blob-num js-line-number" data-line-number="107"></td>
        <td id="LC107" class="blob-code blob-code-inner js-file-line">)</td>
      </tr>
      <tr>
        <td id="L108" class="blob-num js-line-number" data-line-number="108"></td>
        <td id="LC108" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L109" class="blob-num js-line-number" data-line-number="109"></td>
        <td id="LC109" class="blob-code blob-code-inner js-file-line"><span class="pl-k">var</span> <span class="pl-smi">PlatformType_name</span> = <span class="pl-k">map</span>[<span class="pl-k">int32</span>]<span class="pl-k">string</span>{</td>
      </tr>
      <tr>
        <td id="L110" class="blob-num js-line-number" data-line-number="110"></td>
        <td id="LC110" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>PLATFORM_TYPE_UNSPECIFIED<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L111" class="blob-num js-line-number" data-line-number="111"></td>
        <td id="LC111" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">1</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>WINDOWS<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L112" class="blob-num js-line-number" data-line-number="112"></td>
        <td id="LC112" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">2</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>LINUX<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L113" class="blob-num js-line-number" data-line-number="113"></td>
        <td id="LC113" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">3</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>ANDROID<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L114" class="blob-num js-line-number" data-line-number="114"></td>
        <td id="LC114" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">4</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>OSX<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L115" class="blob-num js-line-number" data-line-number="115"></td>
        <td id="LC115" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">5</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>IOS<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L116" class="blob-num js-line-number" data-line-number="116"></td>
        <td id="LC116" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">6</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>ANY_PLATFORM<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L117" class="blob-num js-line-number" data-line-number="117"></td>
        <td id="LC117" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">7</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>ALL_PLATFORMS<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L118" class="blob-num js-line-number" data-line-number="118"></td>
        <td id="LC118" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">8</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>CHROME<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L119" class="blob-num js-line-number" data-line-number="119"></td>
        <td id="LC119" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L120" class="blob-num js-line-number" data-line-number="120"></td>
        <td id="LC120" class="blob-code blob-code-inner js-file-line"><span class="pl-k">var</span> <span class="pl-smi">PlatformType_value</span> = <span class="pl-k">map</span>[<span class="pl-k">string</span>]<span class="pl-k">int32</span>{</td>
      </tr>
      <tr>
        <td id="L121" class="blob-num js-line-number" data-line-number="121"></td>
        <td id="LC121" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>PLATFORM_TYPE_UNSPECIFIED<span class="pl-pds">&quot;</span></span>: <span class="pl-c1">0</span>,</td>
      </tr>
      <tr>
        <td id="L122" class="blob-num js-line-number" data-line-number="122"></td>
        <td id="LC122" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>WINDOWS<span class="pl-pds">&quot;</span></span>:                   <span class="pl-c1">1</span>,</td>
      </tr>
      <tr>
        <td id="L123" class="blob-num js-line-number" data-line-number="123"></td>
        <td id="LC123" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>LINUX<span class="pl-pds">&quot;</span></span>:                     <span class="pl-c1">2</span>,</td>
      </tr>
      <tr>
        <td id="L124" class="blob-num js-line-number" data-line-number="124"></td>
        <td id="LC124" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>ANDROID<span class="pl-pds">&quot;</span></span>:                   <span class="pl-c1">3</span>,</td>
      </tr>
      <tr>
        <td id="L125" class="blob-num js-line-number" data-line-number="125"></td>
        <td id="LC125" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>OSX<span class="pl-pds">&quot;</span></span>:                       <span class="pl-c1">4</span>,</td>
      </tr>
      <tr>
        <td id="L126" class="blob-num js-line-number" data-line-number="126"></td>
        <td id="LC126" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>IOS<span class="pl-pds">&quot;</span></span>:                       <span class="pl-c1">5</span>,</td>
      </tr>
      <tr>
        <td id="L127" class="blob-num js-line-number" data-line-number="127"></td>
        <td id="LC127" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>ANY_PLATFORM<span class="pl-pds">&quot;</span></span>:              <span class="pl-c1">6</span>,</td>
      </tr>
      <tr>
        <td id="L128" class="blob-num js-line-number" data-line-number="128"></td>
        <td id="LC128" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>ALL_PLATFORMS<span class="pl-pds">&quot;</span></span>:             <span class="pl-c1">7</span>,</td>
      </tr>
      <tr>
        <td id="L129" class="blob-num js-line-number" data-line-number="129"></td>
        <td id="LC129" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>CHROME<span class="pl-pds">&quot;</span></span>:                    <span class="pl-c1">8</span>,</td>
      </tr>
      <tr>
        <td id="L130" class="blob-num js-line-number" data-line-number="130"></td>
        <td id="LC130" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L131" class="blob-num js-line-number" data-line-number="131"></td>
        <td id="LC131" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L132" class="blob-num js-line-number" data-line-number="132"></td>
        <td id="LC132" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">x</span> <span class="pl-v">PlatformType</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span> {</td>
      </tr>
      <tr>
        <td id="L133" class="blob-num js-line-number" data-line-number="133"></td>
        <td id="LC133" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> proto.<span class="pl-c1">EnumName</span>(PlatformType_name, <span class="pl-c1">int32</span>(x))</td>
      </tr>
      <tr>
        <td id="L134" class="blob-num js-line-number" data-line-number="134"></td>
        <td id="LC134" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L135" class="blob-num js-line-number" data-line-number="135"></td>
        <td id="LC135" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">PlatformType</span>) <span class="pl-en">EnumDescriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">1</span>} }</td>
      </tr>
      <tr>
        <td id="L136" class="blob-num js-line-number" data-line-number="136"></td>
        <td id="LC136" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L137" class="blob-num js-line-number" data-line-number="137"></td>
        <td id="LC137" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> The ways in which threat entry sets can be compressed.</span></td>
      </tr>
      <tr>
        <td id="L138" class="blob-num js-line-number" data-line-number="138"></td>
        <td id="LC138" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">CompressionType</span> <span class="pl-k">int32</span></td>
      </tr>
      <tr>
        <td id="L139" class="blob-num js-line-number" data-line-number="139"></td>
        <td id="LC139" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L140" class="blob-num js-line-number" data-line-number="140"></td>
        <td id="LC140" class="blob-code blob-code-inner js-file-line"><span class="pl-k">const</span> (</td>
      </tr>
      <tr>
        <td id="L141" class="blob-num js-line-number" data-line-number="141"></td>
        <td id="LC141" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Unknown.</span></td>
      </tr>
      <tr>
        <td id="L142" class="blob-num js-line-number" data-line-number="142"></td>
        <td id="LC142" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">CompressionType_COMPRESSION_TYPE_UNSPECIFIED</span> <span class="pl-v">CompressionType</span> = <span class="pl-c1">0</span></td>
      </tr>
      <tr>
        <td id="L143" class="blob-num js-line-number" data-line-number="143"></td>
        <td id="LC143" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Raw, uncompressed data.</span></td>
      </tr>
      <tr>
        <td id="L144" class="blob-num js-line-number" data-line-number="144"></td>
        <td id="LC144" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">CompressionType_RAW</span> <span class="pl-v">CompressionType</span> = <span class="pl-c1">1</span></td>
      </tr>
      <tr>
        <td id="L145" class="blob-num js-line-number" data-line-number="145"></td>
        <td id="LC145" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Rice-Golomb encoded data.</span></td>
      </tr>
      <tr>
        <td id="L146" class="blob-num js-line-number" data-line-number="146"></td>
        <td id="LC146" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">CompressionType_RICE</span> <span class="pl-v">CompressionType</span> = <span class="pl-c1">2</span></td>
      </tr>
      <tr>
        <td id="L147" class="blob-num js-line-number" data-line-number="147"></td>
        <td id="LC147" class="blob-code blob-code-inner js-file-line">)</td>
      </tr>
      <tr>
        <td id="L148" class="blob-num js-line-number" data-line-number="148"></td>
        <td id="LC148" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L149" class="blob-num js-line-number" data-line-number="149"></td>
        <td id="LC149" class="blob-code blob-code-inner js-file-line"><span class="pl-k">var</span> <span class="pl-smi">CompressionType_name</span> = <span class="pl-k">map</span>[<span class="pl-k">int32</span>]<span class="pl-k">string</span>{</td>
      </tr>
      <tr>
        <td id="L150" class="blob-num js-line-number" data-line-number="150"></td>
        <td id="LC150" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>COMPRESSION_TYPE_UNSPECIFIED<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L151" class="blob-num js-line-number" data-line-number="151"></td>
        <td id="LC151" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">1</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>RAW<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L152" class="blob-num js-line-number" data-line-number="152"></td>
        <td id="LC152" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">2</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>RICE<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L153" class="blob-num js-line-number" data-line-number="153"></td>
        <td id="LC153" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L154" class="blob-num js-line-number" data-line-number="154"></td>
        <td id="LC154" class="blob-code blob-code-inner js-file-line"><span class="pl-k">var</span> <span class="pl-smi">CompressionType_value</span> = <span class="pl-k">map</span>[<span class="pl-k">string</span>]<span class="pl-k">int32</span>{</td>
      </tr>
      <tr>
        <td id="L155" class="blob-num js-line-number" data-line-number="155"></td>
        <td id="LC155" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>COMPRESSION_TYPE_UNSPECIFIED<span class="pl-pds">&quot;</span></span>: <span class="pl-c1">0</span>,</td>
      </tr>
      <tr>
        <td id="L156" class="blob-num js-line-number" data-line-number="156"></td>
        <td id="LC156" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>RAW<span class="pl-pds">&quot;</span></span>:  <span class="pl-c1">1</span>,</td>
      </tr>
      <tr>
        <td id="L157" class="blob-num js-line-number" data-line-number="157"></td>
        <td id="LC157" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>RICE<span class="pl-pds">&quot;</span></span>: <span class="pl-c1">2</span>,</td>
      </tr>
      <tr>
        <td id="L158" class="blob-num js-line-number" data-line-number="158"></td>
        <td id="LC158" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L159" class="blob-num js-line-number" data-line-number="159"></td>
        <td id="LC159" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L160" class="blob-num js-line-number" data-line-number="160"></td>
        <td id="LC160" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">x</span> <span class="pl-v">CompressionType</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span> {</td>
      </tr>
      <tr>
        <td id="L161" class="blob-num js-line-number" data-line-number="161"></td>
        <td id="LC161" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> proto.<span class="pl-c1">EnumName</span>(CompressionType_name, <span class="pl-c1">int32</span>(x))</td>
      </tr>
      <tr>
        <td id="L162" class="blob-num js-line-number" data-line-number="162"></td>
        <td id="LC162" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L163" class="blob-num js-line-number" data-line-number="163"></td>
        <td id="LC163" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">CompressionType</span>) <span class="pl-en">EnumDescriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">2</span>} }</td>
      </tr>
      <tr>
        <td id="L164" class="blob-num js-line-number" data-line-number="164"></td>
        <td id="LC164" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L165" class="blob-num js-line-number" data-line-number="165"></td>
        <td id="LC165" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> Types of entries that pose threats. Threat lists are collections of entries</span></td>
      </tr>
      <tr>
        <td id="L166" class="blob-num js-line-number" data-line-number="166"></td>
        <td id="LC166" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> of a single type.</span></td>
      </tr>
      <tr>
        <td id="L167" class="blob-num js-line-number" data-line-number="167"></td>
        <td id="LC167" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">ThreatEntryType</span> <span class="pl-k">int32</span></td>
      </tr>
      <tr>
        <td id="L168" class="blob-num js-line-number" data-line-number="168"></td>
        <td id="LC168" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L169" class="blob-num js-line-number" data-line-number="169"></td>
        <td id="LC169" class="blob-code blob-code-inner js-file-line"><span class="pl-k">const</span> (</td>
      </tr>
      <tr>
        <td id="L170" class="blob-num js-line-number" data-line-number="170"></td>
        <td id="LC170" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Unspecified.</span></td>
      </tr>
      <tr>
        <td id="L171" class="blob-num js-line-number" data-line-number="171"></td>
        <td id="LC171" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatEntryType_THREAT_ENTRY_TYPE_UNSPECIFIED</span> <span class="pl-v">ThreatEntryType</span> = <span class="pl-c1">0</span></td>
      </tr>
      <tr>
        <td id="L172" class="blob-num js-line-number" data-line-number="172"></td>
        <td id="LC172" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> A URL.</span></td>
      </tr>
      <tr>
        <td id="L173" class="blob-num js-line-number" data-line-number="173"></td>
        <td id="LC173" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatEntryType_URL</span> <span class="pl-v">ThreatEntryType</span> = <span class="pl-c1">1</span></td>
      </tr>
      <tr>
        <td id="L174" class="blob-num js-line-number" data-line-number="174"></td>
        <td id="LC174" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> An executable program.</span></td>
      </tr>
      <tr>
        <td id="L175" class="blob-num js-line-number" data-line-number="175"></td>
        <td id="LC175" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatEntryType_EXECUTABLE</span> <span class="pl-v">ThreatEntryType</span> = <span class="pl-c1">2</span></td>
      </tr>
      <tr>
        <td id="L176" class="blob-num js-line-number" data-line-number="176"></td>
        <td id="LC176" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> An IP range.</span></td>
      </tr>
      <tr>
        <td id="L177" class="blob-num js-line-number" data-line-number="177"></td>
        <td id="LC177" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatEntryType_IP_RANGE</span> <span class="pl-v">ThreatEntryType</span> = <span class="pl-c1">3</span></td>
      </tr>
      <tr>
        <td id="L178" class="blob-num js-line-number" data-line-number="178"></td>
        <td id="LC178" class="blob-code blob-code-inner js-file-line">)</td>
      </tr>
      <tr>
        <td id="L179" class="blob-num js-line-number" data-line-number="179"></td>
        <td id="LC179" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L180" class="blob-num js-line-number" data-line-number="180"></td>
        <td id="LC180" class="blob-code blob-code-inner js-file-line"><span class="pl-k">var</span> <span class="pl-smi">ThreatEntryType_name</span> = <span class="pl-k">map</span>[<span class="pl-k">int32</span>]<span class="pl-k">string</span>{</td>
      </tr>
      <tr>
        <td id="L181" class="blob-num js-line-number" data-line-number="181"></td>
        <td id="LC181" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>THREAT_ENTRY_TYPE_UNSPECIFIED<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L182" class="blob-num js-line-number" data-line-number="182"></td>
        <td id="LC182" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">1</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>URL<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L183" class="blob-num js-line-number" data-line-number="183"></td>
        <td id="LC183" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">2</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>EXECUTABLE<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L184" class="blob-num js-line-number" data-line-number="184"></td>
        <td id="LC184" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">3</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>IP_RANGE<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L185" class="blob-num js-line-number" data-line-number="185"></td>
        <td id="LC185" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L186" class="blob-num js-line-number" data-line-number="186"></td>
        <td id="LC186" class="blob-code blob-code-inner js-file-line"><span class="pl-k">var</span> <span class="pl-smi">ThreatEntryType_value</span> = <span class="pl-k">map</span>[<span class="pl-k">string</span>]<span class="pl-k">int32</span>{</td>
      </tr>
      <tr>
        <td id="L187" class="blob-num js-line-number" data-line-number="187"></td>
        <td id="LC187" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>THREAT_ENTRY_TYPE_UNSPECIFIED<span class="pl-pds">&quot;</span></span>: <span class="pl-c1">0</span>,</td>
      </tr>
      <tr>
        <td id="L188" class="blob-num js-line-number" data-line-number="188"></td>
        <td id="LC188" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>URL<span class="pl-pds">&quot;</span></span>:        <span class="pl-c1">1</span>,</td>
      </tr>
      <tr>
        <td id="L189" class="blob-num js-line-number" data-line-number="189"></td>
        <td id="LC189" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>EXECUTABLE<span class="pl-pds">&quot;</span></span>: <span class="pl-c1">2</span>,</td>
      </tr>
      <tr>
        <td id="L190" class="blob-num js-line-number" data-line-number="190"></td>
        <td id="LC190" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>IP_RANGE<span class="pl-pds">&quot;</span></span>:   <span class="pl-c1">3</span>,</td>
      </tr>
      <tr>
        <td id="L191" class="blob-num js-line-number" data-line-number="191"></td>
        <td id="LC191" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L192" class="blob-num js-line-number" data-line-number="192"></td>
        <td id="LC192" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L193" class="blob-num js-line-number" data-line-number="193"></td>
        <td id="LC193" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">x</span> <span class="pl-v">ThreatEntryType</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span> {</td>
      </tr>
      <tr>
        <td id="L194" class="blob-num js-line-number" data-line-number="194"></td>
        <td id="LC194" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> proto.<span class="pl-c1">EnumName</span>(ThreatEntryType_name, <span class="pl-c1">int32</span>(x))</td>
      </tr>
      <tr>
        <td id="L195" class="blob-num js-line-number" data-line-number="195"></td>
        <td id="LC195" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L196" class="blob-num js-line-number" data-line-number="196"></td>
        <td id="LC196" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">ThreatEntryType</span>) <span class="pl-en">EnumDescriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">3</span>} }</td>
      </tr>
      <tr>
        <td id="L197" class="blob-num js-line-number" data-line-number="197"></td>
        <td id="LC197" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L198" class="blob-num js-line-number" data-line-number="198"></td>
        <td id="LC198" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> The type of response sent to the client.</span></td>
      </tr>
      <tr>
        <td id="L199" class="blob-num js-line-number" data-line-number="199"></td>
        <td id="LC199" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse_ResponseType</span> <span class="pl-k">int32</span></td>
      </tr>
      <tr>
        <td id="L200" class="blob-num js-line-number" data-line-number="200"></td>
        <td id="LC200" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L201" class="blob-num js-line-number" data-line-number="201"></td>
        <td id="LC201" class="blob-code blob-code-inner js-file-line"><span class="pl-k">const</span> (</td>
      </tr>
      <tr>
        <td id="L202" class="blob-num js-line-number" data-line-number="202"></td>
        <td id="LC202" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Unknown.</span></td>
      </tr>
      <tr>
        <td id="L203" class="blob-num js-line-number" data-line-number="203"></td>
        <td id="LC203" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse_RESPONSE_TYPE_UNSPECIFIED</span> <span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse_ResponseType</span> = <span class="pl-c1">0</span></td>
      </tr>
      <tr>
        <td id="L204" class="blob-num js-line-number" data-line-number="204"></td>
        <td id="LC204" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Partial updates are applied to the client&#39;s existing local database.</span></td>
      </tr>
      <tr>
        <td id="L205" class="blob-num js-line-number" data-line-number="205"></td>
        <td id="LC205" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse_PARTIAL_UPDATE</span> <span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse_ResponseType</span> = <span class="pl-c1">1</span></td>
      </tr>
      <tr>
        <td id="L206" class="blob-num js-line-number" data-line-number="206"></td>
        <td id="LC206" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Full updates replace the client&#39;s entire local database. This means</span></td>
      </tr>
      <tr>
        <td id="L207" class="blob-num js-line-number" data-line-number="207"></td>
        <td id="LC207" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> that either the client was seriously out-of-date or the client is</span></td>
      </tr>
      <tr>
        <td id="L208" class="blob-num js-line-number" data-line-number="208"></td>
        <td id="LC208" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> believed to be corrupt.</span></td>
      </tr>
      <tr>
        <td id="L209" class="blob-num js-line-number" data-line-number="209"></td>
        <td id="LC209" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse_FULL_UPDATE</span> <span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse_ResponseType</span> = <span class="pl-c1">2</span></td>
      </tr>
      <tr>
        <td id="L210" class="blob-num js-line-number" data-line-number="210"></td>
        <td id="LC210" class="blob-code blob-code-inner js-file-line">)</td>
      </tr>
      <tr>
        <td id="L211" class="blob-num js-line-number" data-line-number="211"></td>
        <td id="LC211" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L212" class="blob-num js-line-number" data-line-number="212"></td>
        <td id="LC212" class="blob-code blob-code-inner js-file-line"><span class="pl-k">var</span> <span class="pl-smi">FetchThreatListUpdatesResponse_ListUpdateResponse_ResponseType_name</span> = <span class="pl-k">map</span>[<span class="pl-k">int32</span>]<span class="pl-k">string</span>{</td>
      </tr>
      <tr>
        <td id="L213" class="blob-num js-line-number" data-line-number="213"></td>
        <td id="LC213" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>RESPONSE_TYPE_UNSPECIFIED<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L214" class="blob-num js-line-number" data-line-number="214"></td>
        <td id="LC214" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">1</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>PARTIAL_UPDATE<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L215" class="blob-num js-line-number" data-line-number="215"></td>
        <td id="LC215" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">2</span>: <span class="pl-s"><span class="pl-pds">&quot;</span>FULL_UPDATE<span class="pl-pds">&quot;</span></span>,</td>
      </tr>
      <tr>
        <td id="L216" class="blob-num js-line-number" data-line-number="216"></td>
        <td id="LC216" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L217" class="blob-num js-line-number" data-line-number="217"></td>
        <td id="LC217" class="blob-code blob-code-inner js-file-line"><span class="pl-k">var</span> <span class="pl-smi">FetchThreatListUpdatesResponse_ListUpdateResponse_ResponseType_value</span> = <span class="pl-k">map</span>[<span class="pl-k">string</span>]<span class="pl-k">int32</span>{</td>
      </tr>
      <tr>
        <td id="L218" class="blob-num js-line-number" data-line-number="218"></td>
        <td id="LC218" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>RESPONSE_TYPE_UNSPECIFIED<span class="pl-pds">&quot;</span></span>: <span class="pl-c1">0</span>,</td>
      </tr>
      <tr>
        <td id="L219" class="blob-num js-line-number" data-line-number="219"></td>
        <td id="LC219" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>PARTIAL_UPDATE<span class="pl-pds">&quot;</span></span>:            <span class="pl-c1">1</span>,</td>
      </tr>
      <tr>
        <td id="L220" class="blob-num js-line-number" data-line-number="220"></td>
        <td id="LC220" class="blob-code blob-code-inner js-file-line">	<span class="pl-s"><span class="pl-pds">&quot;</span>FULL_UPDATE<span class="pl-pds">&quot;</span></span>:               <span class="pl-c1">2</span>,</td>
      </tr>
      <tr>
        <td id="L221" class="blob-num js-line-number" data-line-number="221"></td>
        <td id="LC221" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L222" class="blob-num js-line-number" data-line-number="222"></td>
        <td id="LC222" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L223" class="blob-num js-line-number" data-line-number="223"></td>
        <td id="LC223" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">x</span> <span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse_ResponseType</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span> {</td>
      </tr>
      <tr>
        <td id="L224" class="blob-num js-line-number" data-line-number="224"></td>
        <td id="LC224" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> proto.<span class="pl-c1">EnumName</span>(FetchThreatListUpdatesResponse_ListUpdateResponse_ResponseType_name, <span class="pl-c1">int32</span>(x))</td>
      </tr>
      <tr>
        <td id="L225" class="blob-num js-line-number" data-line-number="225"></td>
        <td id="LC225" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L226" class="blob-num js-line-number" data-line-number="226"></td>
        <td id="LC226" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse_ResponseType</span>) <span class="pl-en">EnumDescriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) {</td>
      </tr>
      <tr>
        <td id="L227" class="blob-num js-line-number" data-line-number="227"></td>
        <td id="LC227" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">5</span>, <span class="pl-c1">0</span>, <span class="pl-c1">0</span>}</td>
      </tr>
      <tr>
        <td id="L228" class="blob-num js-line-number" data-line-number="228"></td>
        <td id="LC228" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L229" class="blob-num js-line-number" data-line-number="229"></td>
        <td id="LC229" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L230" class="blob-num js-line-number" data-line-number="230"></td>
        <td id="LC230" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> The information regarding one or more threats that a client submits when</span></td>
      </tr>
      <tr>
        <td id="L231" class="blob-num js-line-number" data-line-number="231"></td>
        <td id="LC231" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> checking for matches in threat lists.</span></td>
      </tr>
      <tr>
        <td id="L232" class="blob-num js-line-number" data-line-number="232"></td>
        <td id="LC232" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">ThreatInfo</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L233" class="blob-num js-line-number" data-line-number="233"></td>
        <td id="LC233" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The threat types to be checked.</span></td>
      </tr>
      <tr>
        <td id="L234" class="blob-num js-line-number" data-line-number="234"></td>
        <td id="LC234" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatTypes</span> []<span class="pl-v">ThreatType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,1,rep,name=threat_types,json=threatTypes,enum=safebrowsing_proto.ThreatType&quot; json:&quot;threat_types,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L235" class="blob-num js-line-number" data-line-number="235"></td>
        <td id="LC235" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The platform types to be checked.</span></td>
      </tr>
      <tr>
        <td id="L236" class="blob-num js-line-number" data-line-number="236"></td>
        <td id="LC236" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">PlatformTypes</span> []<span class="pl-v">PlatformType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,2,rep,name=platform_types,json=platformTypes,enum=safebrowsing_proto.PlatformType&quot; json:&quot;platform_types,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L237" class="blob-num js-line-number" data-line-number="237"></td>
        <td id="LC237" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The entry types to be checked.</span></td>
      </tr>
      <tr>
        <td id="L238" class="blob-num js-line-number" data-line-number="238"></td>
        <td id="LC238" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatEntryTypes</span> []<span class="pl-v">ThreatEntryType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,4,rep,name=threat_entry_types,json=threatEntryTypes,enum=safebrowsing_proto.ThreatEntryType&quot; json:&quot;threat_entry_types,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L239" class="blob-num js-line-number" data-line-number="239"></td>
        <td id="LC239" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The threat entries to be checked.</span></td>
      </tr>
      <tr>
        <td id="L240" class="blob-num js-line-number" data-line-number="240"></td>
        <td id="LC240" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatEntries</span> []*ThreatEntry <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,3,rep,name=threat_entries,json=threatEntries&quot; json:&quot;threat_entries,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L241" class="blob-num js-line-number" data-line-number="241"></td>
        <td id="LC241" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L242" class="blob-num js-line-number" data-line-number="242"></td>
        <td id="LC242" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L243" class="blob-num js-line-number" data-line-number="243"></td>
        <td id="LC243" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatInfo</span>) <span class="pl-en">Reset</span></span>()                    { *m = ThreatInfo{} }</td>
      </tr>
      <tr>
        <td id="L244" class="blob-num js-line-number" data-line-number="244"></td>
        <td id="LC244" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatInfo</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L245" class="blob-num js-line-number" data-line-number="245"></td>
        <td id="LC245" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ThreatInfo</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L246" class="blob-num js-line-number" data-line-number="246"></td>
        <td id="LC246" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ThreatInfo</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">0</span>} }</td>
      </tr>
      <tr>
        <td id="L247" class="blob-num js-line-number" data-line-number="247"></td>
        <td id="LC247" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L248" class="blob-num js-line-number" data-line-number="248"></td>
        <td id="LC248" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatInfo</span>) <span class="pl-en">GetThreatEntries</span></span>() []*<span class="pl-v">ThreatEntry</span> {</td>
      </tr>
      <tr>
        <td id="L249" class="blob-num js-line-number" data-line-number="249"></td>
        <td id="LC249" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L250" class="blob-num js-line-number" data-line-number="250"></td>
        <td id="LC250" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">ThreatEntries</span></td>
      </tr>
      <tr>
        <td id="L251" class="blob-num js-line-number" data-line-number="251"></td>
        <td id="LC251" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L252" class="blob-num js-line-number" data-line-number="252"></td>
        <td id="LC252" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L253" class="blob-num js-line-number" data-line-number="253"></td>
        <td id="LC253" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L254" class="blob-num js-line-number" data-line-number="254"></td>
        <td id="LC254" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L255" class="blob-num js-line-number" data-line-number="255"></td>
        <td id="LC255" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> A match when checking a threat entry in the Safe Browsing threat lists.</span></td>
      </tr>
      <tr>
        <td id="L256" class="blob-num js-line-number" data-line-number="256"></td>
        <td id="LC256" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">ThreatMatch</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L257" class="blob-num js-line-number" data-line-number="257"></td>
        <td id="LC257" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The threat type matching this threat.</span></td>
      </tr>
      <tr>
        <td id="L258" class="blob-num js-line-number" data-line-number="258"></td>
        <td id="LC258" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatType</span> <span class="pl-v">ThreatType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,1,opt,name=threat_type,json=threatType,enum=safebrowsing_proto.ThreatType&quot; json:&quot;threat_type,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L259" class="blob-num js-line-number" data-line-number="259"></td>
        <td id="LC259" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The platform type matching this threat.</span></td>
      </tr>
      <tr>
        <td id="L260" class="blob-num js-line-number" data-line-number="260"></td>
        <td id="LC260" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">PlatformType</span> <span class="pl-v">PlatformType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,2,opt,name=platform_type,json=platformType,enum=safebrowsing_proto.PlatformType&quot; json:&quot;platform_type,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L261" class="blob-num js-line-number" data-line-number="261"></td>
        <td id="LC261" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The threat entry type matching this threat.</span></td>
      </tr>
      <tr>
        <td id="L262" class="blob-num js-line-number" data-line-number="262"></td>
        <td id="LC262" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatEntryType</span> <span class="pl-v">ThreatEntryType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,6,opt,name=threat_entry_type,json=threatEntryType,enum=safebrowsing_proto.ThreatEntryType&quot; json:&quot;threat_entry_type,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L263" class="blob-num js-line-number" data-line-number="263"></td>
        <td id="LC263" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The threat matching this threat.</span></td>
      </tr>
      <tr>
        <td id="L264" class="blob-num js-line-number" data-line-number="264"></td>
        <td id="LC264" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Threat</span> *ThreatEntry <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,3,opt,name=threat&quot; json:&quot;threat,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L265" class="blob-num js-line-number" data-line-number="265"></td>
        <td id="LC265" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Optional metadata associated with this threat.</span></td>
      </tr>
      <tr>
        <td id="L266" class="blob-num js-line-number" data-line-number="266"></td>
        <td id="LC266" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatEntryMetadata</span> *ThreatEntryMetadata <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,4,opt,name=threat_entry_metadata,json=threatEntryMetadata&quot; json:&quot;threat_entry_metadata,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L267" class="blob-num js-line-number" data-line-number="267"></td>
        <td id="LC267" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The cache lifetime for the returned match. Clients must not cache this</span></td>
      </tr>
      <tr>
        <td id="L268" class="blob-num js-line-number" data-line-number="268"></td>
        <td id="LC268" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> response for more than this duration to avoid false positives.</span></td>
      </tr>
      <tr>
        <td id="L269" class="blob-num js-line-number" data-line-number="269"></td>
        <td id="LC269" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">CacheDuration</span> *Duration <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,5,opt,name=cache_duration,json=cacheDuration&quot; json:&quot;cache_duration,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L270" class="blob-num js-line-number" data-line-number="270"></td>
        <td id="LC270" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L271" class="blob-num js-line-number" data-line-number="271"></td>
        <td id="LC271" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L272" class="blob-num js-line-number" data-line-number="272"></td>
        <td id="LC272" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatMatch</span>) <span class="pl-en">Reset</span></span>()                    { *m = ThreatMatch{} }</td>
      </tr>
      <tr>
        <td id="L273" class="blob-num js-line-number" data-line-number="273"></td>
        <td id="LC273" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatMatch</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L274" class="blob-num js-line-number" data-line-number="274"></td>
        <td id="LC274" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ThreatMatch</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L275" class="blob-num js-line-number" data-line-number="275"></td>
        <td id="LC275" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ThreatMatch</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">1</span>} }</td>
      </tr>
      <tr>
        <td id="L276" class="blob-num js-line-number" data-line-number="276"></td>
        <td id="LC276" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L277" class="blob-num js-line-number" data-line-number="277"></td>
        <td id="LC277" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatMatch</span>) <span class="pl-en">GetThreat</span></span>() *<span class="pl-v">ThreatEntry</span> {</td>
      </tr>
      <tr>
        <td id="L278" class="blob-num js-line-number" data-line-number="278"></td>
        <td id="LC278" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L279" class="blob-num js-line-number" data-line-number="279"></td>
        <td id="LC279" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">Threat</span></td>
      </tr>
      <tr>
        <td id="L280" class="blob-num js-line-number" data-line-number="280"></td>
        <td id="LC280" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L281" class="blob-num js-line-number" data-line-number="281"></td>
        <td id="LC281" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L282" class="blob-num js-line-number" data-line-number="282"></td>
        <td id="LC282" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L283" class="blob-num js-line-number" data-line-number="283"></td>
        <td id="LC283" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L284" class="blob-num js-line-number" data-line-number="284"></td>
        <td id="LC284" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatMatch</span>) <span class="pl-en">GetThreatEntryMetadata</span></span>() *<span class="pl-v">ThreatEntryMetadata</span> {</td>
      </tr>
      <tr>
        <td id="L285" class="blob-num js-line-number" data-line-number="285"></td>
        <td id="LC285" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L286" class="blob-num js-line-number" data-line-number="286"></td>
        <td id="LC286" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">ThreatEntryMetadata</span></td>
      </tr>
      <tr>
        <td id="L287" class="blob-num js-line-number" data-line-number="287"></td>
        <td id="LC287" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L288" class="blob-num js-line-number" data-line-number="288"></td>
        <td id="LC288" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L289" class="blob-num js-line-number" data-line-number="289"></td>
        <td id="LC289" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L290" class="blob-num js-line-number" data-line-number="290"></td>
        <td id="LC290" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L291" class="blob-num js-line-number" data-line-number="291"></td>
        <td id="LC291" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatMatch</span>) <span class="pl-en">GetCacheDuration</span></span>() *<span class="pl-v">Duration</span> {</td>
      </tr>
      <tr>
        <td id="L292" class="blob-num js-line-number" data-line-number="292"></td>
        <td id="LC292" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L293" class="blob-num js-line-number" data-line-number="293"></td>
        <td id="LC293" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">CacheDuration</span></td>
      </tr>
      <tr>
        <td id="L294" class="blob-num js-line-number" data-line-number="294"></td>
        <td id="LC294" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L295" class="blob-num js-line-number" data-line-number="295"></td>
        <td id="LC295" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L296" class="blob-num js-line-number" data-line-number="296"></td>
        <td id="LC296" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L297" class="blob-num js-line-number" data-line-number="297"></td>
        <td id="LC297" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L298" class="blob-num js-line-number" data-line-number="298"></td>
        <td id="LC298" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> Request to check entries against lists.</span></td>
      </tr>
      <tr>
        <td id="L299" class="blob-num js-line-number" data-line-number="299"></td>
        <td id="LC299" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">FindThreatMatchesRequest</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L300" class="blob-num js-line-number" data-line-number="300"></td>
        <td id="LC300" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The client metadata.</span></td>
      </tr>
      <tr>
        <td id="L301" class="blob-num js-line-number" data-line-number="301"></td>
        <td id="LC301" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Client</span> *ClientInfo <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,1,opt,name=client&quot; json:&quot;client,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L302" class="blob-num js-line-number" data-line-number="302"></td>
        <td id="LC302" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The lists and entries to be checked for matches.</span></td>
      </tr>
      <tr>
        <td id="L303" class="blob-num js-line-number" data-line-number="303"></td>
        <td id="LC303" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatInfo</span> *ThreatInfo <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,2,opt,name=threat_info,json=threatInfo&quot; json:&quot;threat_info,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L304" class="blob-num js-line-number" data-line-number="304"></td>
        <td id="LC304" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L305" class="blob-num js-line-number" data-line-number="305"></td>
        <td id="LC305" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L306" class="blob-num js-line-number" data-line-number="306"></td>
        <td id="LC306" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FindThreatMatchesRequest</span>) <span class="pl-en">Reset</span></span>()                    { *m = FindThreatMatchesRequest{} }</td>
      </tr>
      <tr>
        <td id="L307" class="blob-num js-line-number" data-line-number="307"></td>
        <td id="LC307" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FindThreatMatchesRequest</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L308" class="blob-num js-line-number" data-line-number="308"></td>
        <td id="LC308" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FindThreatMatchesRequest</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L309" class="blob-num js-line-number" data-line-number="309"></td>
        <td id="LC309" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FindThreatMatchesRequest</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">2</span>} }</td>
      </tr>
      <tr>
        <td id="L310" class="blob-num js-line-number" data-line-number="310"></td>
        <td id="LC310" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L311" class="blob-num js-line-number" data-line-number="311"></td>
        <td id="LC311" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FindThreatMatchesRequest</span>) <span class="pl-en">GetClient</span></span>() *<span class="pl-v">ClientInfo</span> {</td>
      </tr>
      <tr>
        <td id="L312" class="blob-num js-line-number" data-line-number="312"></td>
        <td id="LC312" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L313" class="blob-num js-line-number" data-line-number="313"></td>
        <td id="LC313" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">Client</span></td>
      </tr>
      <tr>
        <td id="L314" class="blob-num js-line-number" data-line-number="314"></td>
        <td id="LC314" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L315" class="blob-num js-line-number" data-line-number="315"></td>
        <td id="LC315" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L316" class="blob-num js-line-number" data-line-number="316"></td>
        <td id="LC316" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L317" class="blob-num js-line-number" data-line-number="317"></td>
        <td id="LC317" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L318" class="blob-num js-line-number" data-line-number="318"></td>
        <td id="LC318" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FindThreatMatchesRequest</span>) <span class="pl-en">GetThreatInfo</span></span>() *<span class="pl-v">ThreatInfo</span> {</td>
      </tr>
      <tr>
        <td id="L319" class="blob-num js-line-number" data-line-number="319"></td>
        <td id="LC319" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L320" class="blob-num js-line-number" data-line-number="320"></td>
        <td id="LC320" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">ThreatInfo</span></td>
      </tr>
      <tr>
        <td id="L321" class="blob-num js-line-number" data-line-number="321"></td>
        <td id="LC321" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L322" class="blob-num js-line-number" data-line-number="322"></td>
        <td id="LC322" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L323" class="blob-num js-line-number" data-line-number="323"></td>
        <td id="LC323" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L324" class="blob-num js-line-number" data-line-number="324"></td>
        <td id="LC324" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L325" class="blob-num js-line-number" data-line-number="325"></td>
        <td id="LC325" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> Response type for requests to find threat matches.</span></td>
      </tr>
      <tr>
        <td id="L326" class="blob-num js-line-number" data-line-number="326"></td>
        <td id="LC326" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">FindThreatMatchesResponse</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L327" class="blob-num js-line-number" data-line-number="327"></td>
        <td id="LC327" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The threat list matches.</span></td>
      </tr>
      <tr>
        <td id="L328" class="blob-num js-line-number" data-line-number="328"></td>
        <td id="LC328" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Matches</span> []*ThreatMatch <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,1,rep,name=matches&quot; json:&quot;matches,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L329" class="blob-num js-line-number" data-line-number="329"></td>
        <td id="LC329" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L330" class="blob-num js-line-number" data-line-number="330"></td>
        <td id="LC330" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L331" class="blob-num js-line-number" data-line-number="331"></td>
        <td id="LC331" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FindThreatMatchesResponse</span>) <span class="pl-en">Reset</span></span>()                    { *m = FindThreatMatchesResponse{} }</td>
      </tr>
      <tr>
        <td id="L332" class="blob-num js-line-number" data-line-number="332"></td>
        <td id="LC332" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FindThreatMatchesResponse</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L333" class="blob-num js-line-number" data-line-number="333"></td>
        <td id="LC333" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FindThreatMatchesResponse</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L334" class="blob-num js-line-number" data-line-number="334"></td>
        <td id="LC334" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FindThreatMatchesResponse</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">3</span>} }</td>
      </tr>
      <tr>
        <td id="L335" class="blob-num js-line-number" data-line-number="335"></td>
        <td id="LC335" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L336" class="blob-num js-line-number" data-line-number="336"></td>
        <td id="LC336" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FindThreatMatchesResponse</span>) <span class="pl-en">GetMatches</span></span>() []*<span class="pl-v">ThreatMatch</span> {</td>
      </tr>
      <tr>
        <td id="L337" class="blob-num js-line-number" data-line-number="337"></td>
        <td id="LC337" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L338" class="blob-num js-line-number" data-line-number="338"></td>
        <td id="LC338" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">Matches</span></td>
      </tr>
      <tr>
        <td id="L339" class="blob-num js-line-number" data-line-number="339"></td>
        <td id="LC339" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L340" class="blob-num js-line-number" data-line-number="340"></td>
        <td id="LC340" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L341" class="blob-num js-line-number" data-line-number="341"></td>
        <td id="LC341" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L342" class="blob-num js-line-number" data-line-number="342"></td>
        <td id="LC342" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L343" class="blob-num js-line-number" data-line-number="343"></td>
        <td id="LC343" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> Describes a Safe Browsing API update request. Clients can request updates for</span></td>
      </tr>
      <tr>
        <td id="L344" class="blob-num js-line-number" data-line-number="344"></td>
        <td id="LC344" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> multiple lists in a single request.</span></td>
      </tr>
      <tr>
        <td id="L345" class="blob-num js-line-number" data-line-number="345"></td>
        <td id="LC345" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> NOTE: Field index 2 is unused.</span></td>
      </tr>
      <tr>
        <td id="L346" class="blob-num js-line-number" data-line-number="346"></td>
        <td id="LC346" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">FetchThreatListUpdatesRequest</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L347" class="blob-num js-line-number" data-line-number="347"></td>
        <td id="LC347" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The client metadata.</span></td>
      </tr>
      <tr>
        <td id="L348" class="blob-num js-line-number" data-line-number="348"></td>
        <td id="LC348" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Client</span> *ClientInfo <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,1,opt,name=client&quot; json:&quot;client,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L349" class="blob-num js-line-number" data-line-number="349"></td>
        <td id="LC349" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The requested threat list updates.</span></td>
      </tr>
      <tr>
        <td id="L350" class="blob-num js-line-number" data-line-number="350"></td>
        <td id="LC350" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ListUpdateRequests</span> []*FetchThreatListUpdatesRequest_ListUpdateRequest <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,3,rep,name=list_update_requests,json=listUpdateRequests&quot; json:&quot;list_update_requests,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L351" class="blob-num js-line-number" data-line-number="351"></td>
        <td id="LC351" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L352" class="blob-num js-line-number" data-line-number="352"></td>
        <td id="LC352" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L353" class="blob-num js-line-number" data-line-number="353"></td>
        <td id="LC353" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesRequest</span>) <span class="pl-en">Reset</span></span>()                    { *m = FetchThreatListUpdatesRequest{} }</td>
      </tr>
      <tr>
        <td id="L354" class="blob-num js-line-number" data-line-number="354"></td>
        <td id="LC354" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesRequest</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L355" class="blob-num js-line-number" data-line-number="355"></td>
        <td id="LC355" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FetchThreatListUpdatesRequest</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L356" class="blob-num js-line-number" data-line-number="356"></td>
        <td id="LC356" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FetchThreatListUpdatesRequest</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">4</span>} }</td>
      </tr>
      <tr>
        <td id="L357" class="blob-num js-line-number" data-line-number="357"></td>
        <td id="LC357" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L358" class="blob-num js-line-number" data-line-number="358"></td>
        <td id="LC358" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesRequest</span>) <span class="pl-en">GetClient</span></span>() *<span class="pl-v">ClientInfo</span> {</td>
      </tr>
      <tr>
        <td id="L359" class="blob-num js-line-number" data-line-number="359"></td>
        <td id="LC359" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L360" class="blob-num js-line-number" data-line-number="360"></td>
        <td id="LC360" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">Client</span></td>
      </tr>
      <tr>
        <td id="L361" class="blob-num js-line-number" data-line-number="361"></td>
        <td id="LC361" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L362" class="blob-num js-line-number" data-line-number="362"></td>
        <td id="LC362" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L363" class="blob-num js-line-number" data-line-number="363"></td>
        <td id="LC363" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L364" class="blob-num js-line-number" data-line-number="364"></td>
        <td id="LC364" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L365" class="blob-num js-line-number" data-line-number="365"></td>
        <td id="LC365" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesRequest</span>) <span class="pl-en">GetListUpdateRequests</span></span>() []*<span class="pl-v">FetchThreatListUpdatesRequest_ListUpdateRequest</span> {</td>
      </tr>
      <tr>
        <td id="L366" class="blob-num js-line-number" data-line-number="366"></td>
        <td id="LC366" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L367" class="blob-num js-line-number" data-line-number="367"></td>
        <td id="LC367" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">ListUpdateRequests</span></td>
      </tr>
      <tr>
        <td id="L368" class="blob-num js-line-number" data-line-number="368"></td>
        <td id="LC368" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L369" class="blob-num js-line-number" data-line-number="369"></td>
        <td id="LC369" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L370" class="blob-num js-line-number" data-line-number="370"></td>
        <td id="LC370" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L371" class="blob-num js-line-number" data-line-number="371"></td>
        <td id="LC371" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L372" class="blob-num js-line-number" data-line-number="372"></td>
        <td id="LC372" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> A single list update request.</span></td>
      </tr>
      <tr>
        <td id="L373" class="blob-num js-line-number" data-line-number="373"></td>
        <td id="LC373" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">FetchThreatListUpdatesRequest_ListUpdateRequest</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L374" class="blob-num js-line-number" data-line-number="374"></td>
        <td id="LC374" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The type of threat posed by entries present in the list.</span></td>
      </tr>
      <tr>
        <td id="L375" class="blob-num js-line-number" data-line-number="375"></td>
        <td id="LC375" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatType</span> <span class="pl-v">ThreatType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,1,opt,name=threat_type,json=threatType,enum=safebrowsing_proto.ThreatType&quot; json:&quot;threat_type,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L376" class="blob-num js-line-number" data-line-number="376"></td>
        <td id="LC376" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The type of platform at risk by entries present in the list.</span></td>
      </tr>
      <tr>
        <td id="L377" class="blob-num js-line-number" data-line-number="377"></td>
        <td id="LC377" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">PlatformType</span> <span class="pl-v">PlatformType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,2,opt,name=platform_type,json=platformType,enum=safebrowsing_proto.PlatformType&quot; json:&quot;platform_type,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L378" class="blob-num js-line-number" data-line-number="378"></td>
        <td id="LC378" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The types of entries present in the list.</span></td>
      </tr>
      <tr>
        <td id="L379" class="blob-num js-line-number" data-line-number="379"></td>
        <td id="LC379" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatEntryType</span> <span class="pl-v">ThreatEntryType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,5,opt,name=threat_entry_type,json=threatEntryType,enum=safebrowsing_proto.ThreatEntryType&quot; json:&quot;threat_entry_type,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L380" class="blob-num js-line-number" data-line-number="380"></td>
        <td id="LC380" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The current state of the client for the requested list (the encrypted</span></td>
      </tr>
      <tr>
        <td id="L381" class="blob-num js-line-number" data-line-number="381"></td>
        <td id="LC381" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> ClientState that was sent to the client from the previous update</span></td>
      </tr>
      <tr>
        <td id="L382" class="blob-num js-line-number" data-line-number="382"></td>
        <td id="LC382" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> request).</span></td>
      </tr>
      <tr>
        <td id="L383" class="blob-num js-line-number" data-line-number="383"></td>
        <td id="LC383" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">State</span> []<span class="pl-k">byte</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,3,opt,name=state,proto3&quot; json:&quot;state,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L384" class="blob-num js-line-number" data-line-number="384"></td>
        <td id="LC384" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The constraints associated with this request.</span></td>
      </tr>
      <tr>
        <td id="L385" class="blob-num js-line-number" data-line-number="385"></td>
        <td id="LC385" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Constraints</span> *FetchThreatListUpdatesRequest_ListUpdateRequest_Constraints <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,4,opt,name=constraints&quot; json:&quot;constraints,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L386" class="blob-num js-line-number" data-line-number="386"></td>
        <td id="LC386" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L387" class="blob-num js-line-number" data-line-number="387"></td>
        <td id="LC387" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L388" class="blob-num js-line-number" data-line-number="388"></td>
        <td id="LC388" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesRequest_ListUpdateRequest</span>) <span class="pl-en">Reset</span></span>() {</td>
      </tr>
      <tr>
        <td id="L389" class="blob-num js-line-number" data-line-number="389"></td>
        <td id="LC389" class="blob-code blob-code-inner js-file-line">	*m = FetchThreatListUpdatesRequest_ListUpdateRequest{}</td>
      </tr>
      <tr>
        <td id="L390" class="blob-num js-line-number" data-line-number="390"></td>
        <td id="LC390" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L391" class="blob-num js-line-number" data-line-number="391"></td>
        <td id="LC391" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesRequest_ListUpdateRequest</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span> {</td>
      </tr>
      <tr>
        <td id="L392" class="blob-num js-line-number" data-line-number="392"></td>
        <td id="LC392" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m)</td>
      </tr>
      <tr>
        <td id="L393" class="blob-num js-line-number" data-line-number="393"></td>
        <td id="LC393" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L394" class="blob-num js-line-number" data-line-number="394"></td>
        <td id="LC394" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FetchThreatListUpdatesRequest_ListUpdateRequest</span>) <span class="pl-en">ProtoMessage</span></span>() {}</td>
      </tr>
      <tr>
        <td id="L395" class="blob-num js-line-number" data-line-number="395"></td>
        <td id="LC395" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FetchThreatListUpdatesRequest_ListUpdateRequest</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) {</td>
      </tr>
      <tr>
        <td id="L396" class="blob-num js-line-number" data-line-number="396"></td>
        <td id="LC396" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">4</span>, <span class="pl-c1">0</span>}</td>
      </tr>
      <tr>
        <td id="L397" class="blob-num js-line-number" data-line-number="397"></td>
        <td id="LC397" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L398" class="blob-num js-line-number" data-line-number="398"></td>
        <td id="LC398" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L399" class="blob-num js-line-number" data-line-number="399"></td>
        <td id="LC399" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesRequest_ListUpdateRequest</span>) <span class="pl-en">GetConstraints</span></span>() *<span class="pl-v">FetchThreatListUpdatesRequest_ListUpdateRequest_Constraints</span> {</td>
      </tr>
      <tr>
        <td id="L400" class="blob-num js-line-number" data-line-number="400"></td>
        <td id="LC400" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L401" class="blob-num js-line-number" data-line-number="401"></td>
        <td id="LC401" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">Constraints</span></td>
      </tr>
      <tr>
        <td id="L402" class="blob-num js-line-number" data-line-number="402"></td>
        <td id="LC402" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L403" class="blob-num js-line-number" data-line-number="403"></td>
        <td id="LC403" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L404" class="blob-num js-line-number" data-line-number="404"></td>
        <td id="LC404" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L405" class="blob-num js-line-number" data-line-number="405"></td>
        <td id="LC405" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L406" class="blob-num js-line-number" data-line-number="406"></td>
        <td id="LC406" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> The constraints for this update.</span></td>
      </tr>
      <tr>
        <td id="L407" class="blob-num js-line-number" data-line-number="407"></td>
        <td id="LC407" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">FetchThreatListUpdatesRequest_ListUpdateRequest_Constraints</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L408" class="blob-num js-line-number" data-line-number="408"></td>
        <td id="LC408" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The maximum size in number of entries. The update will not contain more</span></td>
      </tr>
      <tr>
        <td id="L409" class="blob-num js-line-number" data-line-number="409"></td>
        <td id="LC409" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> entries than this value.  This should be a power of 2 between 2**10 and</span></td>
      </tr>
      <tr>
        <td id="L410" class="blob-num js-line-number" data-line-number="410"></td>
        <td id="LC410" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> 2**20.  If zero, no update size limit is set.</span></td>
      </tr>
      <tr>
        <td id="L411" class="blob-num js-line-number" data-line-number="411"></td>
        <td id="LC411" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">MaxUpdateEntries</span> <span class="pl-k">int32</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,1,opt,name=max_update_entries,json=maxUpdateEntries&quot; json:&quot;max_update_entries,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L412" class="blob-num js-line-number" data-line-number="412"></td>
        <td id="LC412" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Sets the maximum number of entries that the client is willing to have</span></td>
      </tr>
      <tr>
        <td id="L413" class="blob-num js-line-number" data-line-number="413"></td>
        <td id="LC413" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> in the local database. This should be a power of 2 between 2**10 and</span></td>
      </tr>
      <tr>
        <td id="L414" class="blob-num js-line-number" data-line-number="414"></td>
        <td id="LC414" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> 2**20. If zero, no database size limit is set.</span></td>
      </tr>
      <tr>
        <td id="L415" class="blob-num js-line-number" data-line-number="415"></td>
        <td id="LC415" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">MaxDatabaseEntries</span> <span class="pl-k">int32</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,2,opt,name=max_database_entries,json=maxDatabaseEntries&quot; json:&quot;max_database_entries,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L416" class="blob-num js-line-number" data-line-number="416"></td>
        <td id="LC416" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Requests the list for a specific geographic location. If not set the</span></td>
      </tr>
      <tr>
        <td id="L417" class="blob-num js-line-number" data-line-number="417"></td>
        <td id="LC417" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> server may pick that value based on the user&#39;s IP address. Expects ISO</span></td>
      </tr>
      <tr>
        <td id="L418" class="blob-num js-line-number" data-line-number="418"></td>
        <td id="LC418" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> 3166-1 alpha-2 format.</span></td>
      </tr>
      <tr>
        <td id="L419" class="blob-num js-line-number" data-line-number="419"></td>
        <td id="LC419" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Region</span> <span class="pl-k">string</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,3,opt,name=region&quot; json:&quot;region,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L420" class="blob-num js-line-number" data-line-number="420"></td>
        <td id="LC420" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The compression types supported by the client.</span></td>
      </tr>
      <tr>
        <td id="L421" class="blob-num js-line-number" data-line-number="421"></td>
        <td id="LC421" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">SupportedCompressions</span> []<span class="pl-v">CompressionType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,4,rep,name=supported_compressions,json=supportedCompressions,enum=safebrowsing_proto.CompressionType&quot; json:&quot;supported_compressions,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L422" class="blob-num js-line-number" data-line-number="422"></td>
        <td id="LC422" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L423" class="blob-num js-line-number" data-line-number="423"></td>
        <td id="LC423" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L424" class="blob-num js-line-number" data-line-number="424"></td>
        <td id="LC424" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesRequest_ListUpdateRequest_Constraints</span>) <span class="pl-en">Reset</span></span>() {</td>
      </tr>
      <tr>
        <td id="L425" class="blob-num js-line-number" data-line-number="425"></td>
        <td id="LC425" class="blob-code blob-code-inner js-file-line">	*m = FetchThreatListUpdatesRequest_ListUpdateRequest_Constraints{}</td>
      </tr>
      <tr>
        <td id="L426" class="blob-num js-line-number" data-line-number="426"></td>
        <td id="LC426" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L427" class="blob-num js-line-number" data-line-number="427"></td>
        <td id="LC427" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesRequest_ListUpdateRequest_Constraints</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span> {</td>
      </tr>
      <tr>
        <td id="L428" class="blob-num js-line-number" data-line-number="428"></td>
        <td id="LC428" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m)</td>
      </tr>
      <tr>
        <td id="L429" class="blob-num js-line-number" data-line-number="429"></td>
        <td id="LC429" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L430" class="blob-num js-line-number" data-line-number="430"></td>
        <td id="LC430" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FetchThreatListUpdatesRequest_ListUpdateRequest_Constraints</span>) <span class="pl-en">ProtoMessage</span></span>() {}</td>
      </tr>
      <tr>
        <td id="L431" class="blob-num js-line-number" data-line-number="431"></td>
        <td id="LC431" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FetchThreatListUpdatesRequest_ListUpdateRequest_Constraints</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) {</td>
      </tr>
      <tr>
        <td id="L432" class="blob-num js-line-number" data-line-number="432"></td>
        <td id="LC432" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">4</span>, <span class="pl-c1">0</span>, <span class="pl-c1">0</span>}</td>
      </tr>
      <tr>
        <td id="L433" class="blob-num js-line-number" data-line-number="433"></td>
        <td id="LC433" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L434" class="blob-num js-line-number" data-line-number="434"></td>
        <td id="LC434" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L435" class="blob-num js-line-number" data-line-number="435"></td>
        <td id="LC435" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> Response type for threat list update requests.</span></td>
      </tr>
      <tr>
        <td id="L436" class="blob-num js-line-number" data-line-number="436"></td>
        <td id="LC436" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">FetchThreatListUpdatesResponse</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L437" class="blob-num js-line-number" data-line-number="437"></td>
        <td id="LC437" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The list updates requested by the clients.</span></td>
      </tr>
      <tr>
        <td id="L438" class="blob-num js-line-number" data-line-number="438"></td>
        <td id="LC438" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ListUpdateResponses</span> []*FetchThreatListUpdatesResponse_ListUpdateResponse <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,1,rep,name=list_update_responses,json=listUpdateResponses&quot; json:&quot;list_update_responses,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L439" class="blob-num js-line-number" data-line-number="439"></td>
        <td id="LC439" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The minimum duration the client must wait before issuing any update</span></td>
      </tr>
      <tr>
        <td id="L440" class="blob-num js-line-number" data-line-number="440"></td>
        <td id="LC440" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> request. If this field is not set clients may update as soon as they want.</span></td>
      </tr>
      <tr>
        <td id="L441" class="blob-num js-line-number" data-line-number="441"></td>
        <td id="LC441" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">MinimumWaitDuration</span> *Duration <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,2,opt,name=minimum_wait_duration,json=minimumWaitDuration&quot; json:&quot;minimum_wait_duration,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L442" class="blob-num js-line-number" data-line-number="442"></td>
        <td id="LC442" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L443" class="blob-num js-line-number" data-line-number="443"></td>
        <td id="LC443" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L444" class="blob-num js-line-number" data-line-number="444"></td>
        <td id="LC444" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesResponse</span>) <span class="pl-en">Reset</span></span>()                    { *m = FetchThreatListUpdatesResponse{} }</td>
      </tr>
      <tr>
        <td id="L445" class="blob-num js-line-number" data-line-number="445"></td>
        <td id="LC445" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesResponse</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L446" class="blob-num js-line-number" data-line-number="446"></td>
        <td id="LC446" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FetchThreatListUpdatesResponse</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L447" class="blob-num js-line-number" data-line-number="447"></td>
        <td id="LC447" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FetchThreatListUpdatesResponse</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">5</span>} }</td>
      </tr>
      <tr>
        <td id="L448" class="blob-num js-line-number" data-line-number="448"></td>
        <td id="LC448" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L449" class="blob-num js-line-number" data-line-number="449"></td>
        <td id="LC449" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesResponse</span>) <span class="pl-en">GetListUpdateResponses</span></span>() []*<span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse</span> {</td>
      </tr>
      <tr>
        <td id="L450" class="blob-num js-line-number" data-line-number="450"></td>
        <td id="LC450" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L451" class="blob-num js-line-number" data-line-number="451"></td>
        <td id="LC451" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">ListUpdateResponses</span></td>
      </tr>
      <tr>
        <td id="L452" class="blob-num js-line-number" data-line-number="452"></td>
        <td id="LC452" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L453" class="blob-num js-line-number" data-line-number="453"></td>
        <td id="LC453" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L454" class="blob-num js-line-number" data-line-number="454"></td>
        <td id="LC454" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L455" class="blob-num js-line-number" data-line-number="455"></td>
        <td id="LC455" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L456" class="blob-num js-line-number" data-line-number="456"></td>
        <td id="LC456" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesResponse</span>) <span class="pl-en">GetMinimumWaitDuration</span></span>() *<span class="pl-v">Duration</span> {</td>
      </tr>
      <tr>
        <td id="L457" class="blob-num js-line-number" data-line-number="457"></td>
        <td id="LC457" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L458" class="blob-num js-line-number" data-line-number="458"></td>
        <td id="LC458" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">MinimumWaitDuration</span></td>
      </tr>
      <tr>
        <td id="L459" class="blob-num js-line-number" data-line-number="459"></td>
        <td id="LC459" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L460" class="blob-num js-line-number" data-line-number="460"></td>
        <td id="LC460" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L461" class="blob-num js-line-number" data-line-number="461"></td>
        <td id="LC461" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L462" class="blob-num js-line-number" data-line-number="462"></td>
        <td id="LC462" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L463" class="blob-num js-line-number" data-line-number="463"></td>
        <td id="LC463" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> An update to an individual list.</span></td>
      </tr>
      <tr>
        <td id="L464" class="blob-num js-line-number" data-line-number="464"></td>
        <td id="LC464" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L465" class="blob-num js-line-number" data-line-number="465"></td>
        <td id="LC465" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The threat type for which data is returned.</span></td>
      </tr>
      <tr>
        <td id="L466" class="blob-num js-line-number" data-line-number="466"></td>
        <td id="LC466" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatType</span> <span class="pl-v">ThreatType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,1,opt,name=threat_type,json=threatType,enum=safebrowsing_proto.ThreatType&quot; json:&quot;threat_type,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L467" class="blob-num js-line-number" data-line-number="467"></td>
        <td id="LC467" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The format of the threats.</span></td>
      </tr>
      <tr>
        <td id="L468" class="blob-num js-line-number" data-line-number="468"></td>
        <td id="LC468" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatEntryType</span> <span class="pl-v">ThreatEntryType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,2,opt,name=threat_entry_type,json=threatEntryType,enum=safebrowsing_proto.ThreatEntryType&quot; json:&quot;threat_entry_type,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L469" class="blob-num js-line-number" data-line-number="469"></td>
        <td id="LC469" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The platform type for which data is returned.</span></td>
      </tr>
      <tr>
        <td id="L470" class="blob-num js-line-number" data-line-number="470"></td>
        <td id="LC470" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">PlatformType</span> <span class="pl-v">PlatformType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,3,opt,name=platform_type,json=platformType,enum=safebrowsing_proto.PlatformType&quot; json:&quot;platform_type,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L471" class="blob-num js-line-number" data-line-number="471"></td>
        <td id="LC471" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The type of response. This may indicate that an action is required by the</span></td>
      </tr>
      <tr>
        <td id="L472" class="blob-num js-line-number" data-line-number="472"></td>
        <td id="LC472" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> client when the response is received.</span></td>
      </tr>
      <tr>
        <td id="L473" class="blob-num js-line-number" data-line-number="473"></td>
        <td id="LC473" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ResponseType</span> <span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse_ResponseType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,4,opt,name=response_type,json=responseType,enum=safebrowsing_proto.FetchThreatListUpdatesResponse_ListUpdateResponse_ResponseType&quot; json:&quot;response_type,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L474" class="blob-num js-line-number" data-line-number="474"></td>
        <td id="LC474" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> A set of entries to add to a local threat type&#39;s list. Repeated to allow</span></td>
      </tr>
      <tr>
        <td id="L475" class="blob-num js-line-number" data-line-number="475"></td>
        <td id="LC475" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> for a combination of compressed and raw data to be sent in a single</span></td>
      </tr>
      <tr>
        <td id="L476" class="blob-num js-line-number" data-line-number="476"></td>
        <td id="LC476" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> response.</span></td>
      </tr>
      <tr>
        <td id="L477" class="blob-num js-line-number" data-line-number="477"></td>
        <td id="LC477" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Additions</span> []*ThreatEntrySet <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,5,rep,name=additions&quot; json:&quot;additions,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L478" class="blob-num js-line-number" data-line-number="478"></td>
        <td id="LC478" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> A set of entries to remove from a local threat type&#39;s list. Repeated for</span></td>
      </tr>
      <tr>
        <td id="L479" class="blob-num js-line-number" data-line-number="479"></td>
        <td id="LC479" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> the same reason as above.</span></td>
      </tr>
      <tr>
        <td id="L480" class="blob-num js-line-number" data-line-number="480"></td>
        <td id="LC480" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Removals</span> []*ThreatEntrySet <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,6,rep,name=removals&quot; json:&quot;removals,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L481" class="blob-num js-line-number" data-line-number="481"></td>
        <td id="LC481" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The new client state, in encrypted format. Opaque to clients.</span></td>
      </tr>
      <tr>
        <td id="L482" class="blob-num js-line-number" data-line-number="482"></td>
        <td id="LC482" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">NewClientState</span> []<span class="pl-k">byte</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,7,opt,name=new_client_state,json=newClientState,proto3&quot; json:&quot;new_client_state,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L483" class="blob-num js-line-number" data-line-number="483"></td>
        <td id="LC483" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The expected SHA256 hash of the client state; that is, of the sorted list</span></td>
      </tr>
      <tr>
        <td id="L484" class="blob-num js-line-number" data-line-number="484"></td>
        <td id="LC484" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> of all hashes present in the database after applying the provided update.</span></td>
      </tr>
      <tr>
        <td id="L485" class="blob-num js-line-number" data-line-number="485"></td>
        <td id="LC485" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> If the client state doesn&#39;t match the expected state, the client must</span></td>
      </tr>
      <tr>
        <td id="L486" class="blob-num js-line-number" data-line-number="486"></td>
        <td id="LC486" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> disregard this update and retry later.</span></td>
      </tr>
      <tr>
        <td id="L487" class="blob-num js-line-number" data-line-number="487"></td>
        <td id="LC487" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Checksum</span> *Checksum <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,8,opt,name=checksum&quot; json:&quot;checksum,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L488" class="blob-num js-line-number" data-line-number="488"></td>
        <td id="LC488" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L489" class="blob-num js-line-number" data-line-number="489"></td>
        <td id="LC489" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L490" class="blob-num js-line-number" data-line-number="490"></td>
        <td id="LC490" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse</span>) <span class="pl-en">Reset</span></span>() {</td>
      </tr>
      <tr>
        <td id="L491" class="blob-num js-line-number" data-line-number="491"></td>
        <td id="LC491" class="blob-code blob-code-inner js-file-line">	*m = FetchThreatListUpdatesResponse_ListUpdateResponse{}</td>
      </tr>
      <tr>
        <td id="L492" class="blob-num js-line-number" data-line-number="492"></td>
        <td id="LC492" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L493" class="blob-num js-line-number" data-line-number="493"></td>
        <td id="LC493" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span> {</td>
      </tr>
      <tr>
        <td id="L494" class="blob-num js-line-number" data-line-number="494"></td>
        <td id="LC494" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m)</td>
      </tr>
      <tr>
        <td id="L495" class="blob-num js-line-number" data-line-number="495"></td>
        <td id="LC495" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L496" class="blob-num js-line-number" data-line-number="496"></td>
        <td id="LC496" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse</span>) <span class="pl-en">ProtoMessage</span></span>() {}</td>
      </tr>
      <tr>
        <td id="L497" class="blob-num js-line-number" data-line-number="497"></td>
        <td id="LC497" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) {</td>
      </tr>
      <tr>
        <td id="L498" class="blob-num js-line-number" data-line-number="498"></td>
        <td id="LC498" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">5</span>, <span class="pl-c1">0</span>}</td>
      </tr>
      <tr>
        <td id="L499" class="blob-num js-line-number" data-line-number="499"></td>
        <td id="LC499" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L500" class="blob-num js-line-number" data-line-number="500"></td>
        <td id="LC500" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L501" class="blob-num js-line-number" data-line-number="501"></td>
        <td id="LC501" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse</span>) <span class="pl-en">GetAdditions</span></span>() []*<span class="pl-v">ThreatEntrySet</span> {</td>
      </tr>
      <tr>
        <td id="L502" class="blob-num js-line-number" data-line-number="502"></td>
        <td id="LC502" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L503" class="blob-num js-line-number" data-line-number="503"></td>
        <td id="LC503" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">Additions</span></td>
      </tr>
      <tr>
        <td id="L504" class="blob-num js-line-number" data-line-number="504"></td>
        <td id="LC504" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L505" class="blob-num js-line-number" data-line-number="505"></td>
        <td id="LC505" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L506" class="blob-num js-line-number" data-line-number="506"></td>
        <td id="LC506" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L507" class="blob-num js-line-number" data-line-number="507"></td>
        <td id="LC507" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L508" class="blob-num js-line-number" data-line-number="508"></td>
        <td id="LC508" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse</span>) <span class="pl-en">GetRemovals</span></span>() []*<span class="pl-v">ThreatEntrySet</span> {</td>
      </tr>
      <tr>
        <td id="L509" class="blob-num js-line-number" data-line-number="509"></td>
        <td id="LC509" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L510" class="blob-num js-line-number" data-line-number="510"></td>
        <td id="LC510" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">Removals</span></td>
      </tr>
      <tr>
        <td id="L511" class="blob-num js-line-number" data-line-number="511"></td>
        <td id="LC511" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L512" class="blob-num js-line-number" data-line-number="512"></td>
        <td id="LC512" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L513" class="blob-num js-line-number" data-line-number="513"></td>
        <td id="LC513" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L514" class="blob-num js-line-number" data-line-number="514"></td>
        <td id="LC514" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L515" class="blob-num js-line-number" data-line-number="515"></td>
        <td id="LC515" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FetchThreatListUpdatesResponse_ListUpdateResponse</span>) <span class="pl-en">GetChecksum</span></span>() *<span class="pl-v">Checksum</span> {</td>
      </tr>
      <tr>
        <td id="L516" class="blob-num js-line-number" data-line-number="516"></td>
        <td id="LC516" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L517" class="blob-num js-line-number" data-line-number="517"></td>
        <td id="LC517" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">Checksum</span></td>
      </tr>
      <tr>
        <td id="L518" class="blob-num js-line-number" data-line-number="518"></td>
        <td id="LC518" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L519" class="blob-num js-line-number" data-line-number="519"></td>
        <td id="LC519" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L520" class="blob-num js-line-number" data-line-number="520"></td>
        <td id="LC520" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L521" class="blob-num js-line-number" data-line-number="521"></td>
        <td id="LC521" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L522" class="blob-num js-line-number" data-line-number="522"></td>
        <td id="LC522" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> Request to return full hashes matched by the provided hash prefixes.</span></td>
      </tr>
      <tr>
        <td id="L523" class="blob-num js-line-number" data-line-number="523"></td>
        <td id="LC523" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">FindFullHashesRequest</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L524" class="blob-num js-line-number" data-line-number="524"></td>
        <td id="LC524" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The client metadata.</span></td>
      </tr>
      <tr>
        <td id="L525" class="blob-num js-line-number" data-line-number="525"></td>
        <td id="LC525" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Client</span> *ClientInfo <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,1,opt,name=client&quot; json:&quot;client,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L526" class="blob-num js-line-number" data-line-number="526"></td>
        <td id="LC526" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The current client states for each of the client&#39;s local threat lists.</span></td>
      </tr>
      <tr>
        <td id="L527" class="blob-num js-line-number" data-line-number="527"></td>
        <td id="LC527" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ClientStates</span> [][]<span class="pl-k">byte</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,2,rep,name=client_states,json=clientStates,proto3&quot; json:&quot;client_states,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L528" class="blob-num js-line-number" data-line-number="528"></td>
        <td id="LC528" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The lists and hashes to be checked.</span></td>
      </tr>
      <tr>
        <td id="L529" class="blob-num js-line-number" data-line-number="529"></td>
        <td id="LC529" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatInfo</span> *ThreatInfo <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,3,opt,name=threat_info,json=threatInfo&quot; json:&quot;threat_info,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L530" class="blob-num js-line-number" data-line-number="530"></td>
        <td id="LC530" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L531" class="blob-num js-line-number" data-line-number="531"></td>
        <td id="LC531" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L532" class="blob-num js-line-number" data-line-number="532"></td>
        <td id="LC532" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FindFullHashesRequest</span>) <span class="pl-en">Reset</span></span>()                    { *m = FindFullHashesRequest{} }</td>
      </tr>
      <tr>
        <td id="L533" class="blob-num js-line-number" data-line-number="533"></td>
        <td id="LC533" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FindFullHashesRequest</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L534" class="blob-num js-line-number" data-line-number="534"></td>
        <td id="LC534" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FindFullHashesRequest</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L535" class="blob-num js-line-number" data-line-number="535"></td>
        <td id="LC535" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FindFullHashesRequest</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">6</span>} }</td>
      </tr>
      <tr>
        <td id="L536" class="blob-num js-line-number" data-line-number="536"></td>
        <td id="LC536" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L537" class="blob-num js-line-number" data-line-number="537"></td>
        <td id="LC537" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FindFullHashesRequest</span>) <span class="pl-en">GetClient</span></span>() *<span class="pl-v">ClientInfo</span> {</td>
      </tr>
      <tr>
        <td id="L538" class="blob-num js-line-number" data-line-number="538"></td>
        <td id="LC538" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L539" class="blob-num js-line-number" data-line-number="539"></td>
        <td id="LC539" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">Client</span></td>
      </tr>
      <tr>
        <td id="L540" class="blob-num js-line-number" data-line-number="540"></td>
        <td id="LC540" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L541" class="blob-num js-line-number" data-line-number="541"></td>
        <td id="LC541" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L542" class="blob-num js-line-number" data-line-number="542"></td>
        <td id="LC542" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L543" class="blob-num js-line-number" data-line-number="543"></td>
        <td id="LC543" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L544" class="blob-num js-line-number" data-line-number="544"></td>
        <td id="LC544" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FindFullHashesRequest</span>) <span class="pl-en">GetThreatInfo</span></span>() *<span class="pl-v">ThreatInfo</span> {</td>
      </tr>
      <tr>
        <td id="L545" class="blob-num js-line-number" data-line-number="545"></td>
        <td id="LC545" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L546" class="blob-num js-line-number" data-line-number="546"></td>
        <td id="LC546" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">ThreatInfo</span></td>
      </tr>
      <tr>
        <td id="L547" class="blob-num js-line-number" data-line-number="547"></td>
        <td id="LC547" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L548" class="blob-num js-line-number" data-line-number="548"></td>
        <td id="LC548" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L549" class="blob-num js-line-number" data-line-number="549"></td>
        <td id="LC549" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L550" class="blob-num js-line-number" data-line-number="550"></td>
        <td id="LC550" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L551" class="blob-num js-line-number" data-line-number="551"></td>
        <td id="LC551" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> Response type for requests to find full hashes.</span></td>
      </tr>
      <tr>
        <td id="L552" class="blob-num js-line-number" data-line-number="552"></td>
        <td id="LC552" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">FindFullHashesResponse</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L553" class="blob-num js-line-number" data-line-number="553"></td>
        <td id="LC553" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The full hashes that matched the requested prefixes.</span></td>
      </tr>
      <tr>
        <td id="L554" class="blob-num js-line-number" data-line-number="554"></td>
        <td id="LC554" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Matches</span> []*ThreatMatch <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,1,rep,name=matches&quot; json:&quot;matches,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L555" class="blob-num js-line-number" data-line-number="555"></td>
        <td id="LC555" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The minimum duration the client must wait before issuing any find hashes</span></td>
      </tr>
      <tr>
        <td id="L556" class="blob-num js-line-number" data-line-number="556"></td>
        <td id="LC556" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> request. If this field is not set, clients can issue a request as soon as</span></td>
      </tr>
      <tr>
        <td id="L557" class="blob-num js-line-number" data-line-number="557"></td>
        <td id="LC557" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> they want.</span></td>
      </tr>
      <tr>
        <td id="L558" class="blob-num js-line-number" data-line-number="558"></td>
        <td id="LC558" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">MinimumWaitDuration</span> *Duration <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,2,opt,name=minimum_wait_duration,json=minimumWaitDuration&quot; json:&quot;minimum_wait_duration,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L559" class="blob-num js-line-number" data-line-number="559"></td>
        <td id="LC559" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> For requested entities that did not match the threat list, how long to</span></td>
      </tr>
      <tr>
        <td id="L560" class="blob-num js-line-number" data-line-number="560"></td>
        <td id="LC560" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> cache the response.</span></td>
      </tr>
      <tr>
        <td id="L561" class="blob-num js-line-number" data-line-number="561"></td>
        <td id="LC561" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">NegativeCacheDuration</span> *Duration <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,3,opt,name=negative_cache_duration,json=negativeCacheDuration&quot; json:&quot;negative_cache_duration,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L562" class="blob-num js-line-number" data-line-number="562"></td>
        <td id="LC562" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L563" class="blob-num js-line-number" data-line-number="563"></td>
        <td id="LC563" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L564" class="blob-num js-line-number" data-line-number="564"></td>
        <td id="LC564" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FindFullHashesResponse</span>) <span class="pl-en">Reset</span></span>()                    { *m = FindFullHashesResponse{} }</td>
      </tr>
      <tr>
        <td id="L565" class="blob-num js-line-number" data-line-number="565"></td>
        <td id="LC565" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FindFullHashesResponse</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L566" class="blob-num js-line-number" data-line-number="566"></td>
        <td id="LC566" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FindFullHashesResponse</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L567" class="blob-num js-line-number" data-line-number="567"></td>
        <td id="LC567" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">FindFullHashesResponse</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">7</span>} }</td>
      </tr>
      <tr>
        <td id="L568" class="blob-num js-line-number" data-line-number="568"></td>
        <td id="LC568" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L569" class="blob-num js-line-number" data-line-number="569"></td>
        <td id="LC569" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FindFullHashesResponse</span>) <span class="pl-en">GetMatches</span></span>() []*<span class="pl-v">ThreatMatch</span> {</td>
      </tr>
      <tr>
        <td id="L570" class="blob-num js-line-number" data-line-number="570"></td>
        <td id="LC570" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L571" class="blob-num js-line-number" data-line-number="571"></td>
        <td id="LC571" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">Matches</span></td>
      </tr>
      <tr>
        <td id="L572" class="blob-num js-line-number" data-line-number="572"></td>
        <td id="LC572" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L573" class="blob-num js-line-number" data-line-number="573"></td>
        <td id="LC573" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L574" class="blob-num js-line-number" data-line-number="574"></td>
        <td id="LC574" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L575" class="blob-num js-line-number" data-line-number="575"></td>
        <td id="LC575" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L576" class="blob-num js-line-number" data-line-number="576"></td>
        <td id="LC576" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FindFullHashesResponse</span>) <span class="pl-en">GetMinimumWaitDuration</span></span>() *<span class="pl-v">Duration</span> {</td>
      </tr>
      <tr>
        <td id="L577" class="blob-num js-line-number" data-line-number="577"></td>
        <td id="LC577" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L578" class="blob-num js-line-number" data-line-number="578"></td>
        <td id="LC578" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">MinimumWaitDuration</span></td>
      </tr>
      <tr>
        <td id="L579" class="blob-num js-line-number" data-line-number="579"></td>
        <td id="LC579" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L580" class="blob-num js-line-number" data-line-number="580"></td>
        <td id="LC580" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L581" class="blob-num js-line-number" data-line-number="581"></td>
        <td id="LC581" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L582" class="blob-num js-line-number" data-line-number="582"></td>
        <td id="LC582" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L583" class="blob-num js-line-number" data-line-number="583"></td>
        <td id="LC583" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">FindFullHashesResponse</span>) <span class="pl-en">GetNegativeCacheDuration</span></span>() *<span class="pl-v">Duration</span> {</td>
      </tr>
      <tr>
        <td id="L584" class="blob-num js-line-number" data-line-number="584"></td>
        <td id="LC584" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L585" class="blob-num js-line-number" data-line-number="585"></td>
        <td id="LC585" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">NegativeCacheDuration</span></td>
      </tr>
      <tr>
        <td id="L586" class="blob-num js-line-number" data-line-number="586"></td>
        <td id="LC586" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L587" class="blob-num js-line-number" data-line-number="587"></td>
        <td id="LC587" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L588" class="blob-num js-line-number" data-line-number="588"></td>
        <td id="LC588" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L589" class="blob-num js-line-number" data-line-number="589"></td>
        <td id="LC589" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L590" class="blob-num js-line-number" data-line-number="590"></td>
        <td id="LC590" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> The client metadata associated with Safe Browsing API requests.</span></td>
      </tr>
      <tr>
        <td id="L591" class="blob-num js-line-number" data-line-number="591"></td>
        <td id="LC591" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">ClientInfo</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L592" class="blob-num js-line-number" data-line-number="592"></td>
        <td id="LC592" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> A client ID that (hopefully) uniquely identifies the client implementation</span></td>
      </tr>
      <tr>
        <td id="L593" class="blob-num js-line-number" data-line-number="593"></td>
        <td id="LC593" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> of the Safe Browsing API.</span></td>
      </tr>
      <tr>
        <td id="L594" class="blob-num js-line-number" data-line-number="594"></td>
        <td id="LC594" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ClientId</span> <span class="pl-k">string</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,1,opt,name=client_id,json=clientId&quot; json:&quot;client_id,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L595" class="blob-num js-line-number" data-line-number="595"></td>
        <td id="LC595" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The version of the client implementation.</span></td>
      </tr>
      <tr>
        <td id="L596" class="blob-num js-line-number" data-line-number="596"></td>
        <td id="LC596" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ClientVersion</span> <span class="pl-k">string</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,2,opt,name=client_version,json=clientVersion&quot; json:&quot;client_version,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L597" class="blob-num js-line-number" data-line-number="597"></td>
        <td id="LC597" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L598" class="blob-num js-line-number" data-line-number="598"></td>
        <td id="LC598" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L599" class="blob-num js-line-number" data-line-number="599"></td>
        <td id="LC599" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ClientInfo</span>) <span class="pl-en">Reset</span></span>()                    { *m = ClientInfo{} }</td>
      </tr>
      <tr>
        <td id="L600" class="blob-num js-line-number" data-line-number="600"></td>
        <td id="LC600" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ClientInfo</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L601" class="blob-num js-line-number" data-line-number="601"></td>
        <td id="LC601" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ClientInfo</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L602" class="blob-num js-line-number" data-line-number="602"></td>
        <td id="LC602" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ClientInfo</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">8</span>} }</td>
      </tr>
      <tr>
        <td id="L603" class="blob-num js-line-number" data-line-number="603"></td>
        <td id="LC603" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L604" class="blob-num js-line-number" data-line-number="604"></td>
        <td id="LC604" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> The expected state of a client&#39;s local database.</span></td>
      </tr>
      <tr>
        <td id="L605" class="blob-num js-line-number" data-line-number="605"></td>
        <td id="LC605" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">Checksum</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L606" class="blob-num js-line-number" data-line-number="606"></td>
        <td id="LC606" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The SHA256 hash of the client state; that is, of the sorted list of all</span></td>
      </tr>
      <tr>
        <td id="L607" class="blob-num js-line-number" data-line-number="607"></td>
        <td id="LC607" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> hashes present in the database.</span></td>
      </tr>
      <tr>
        <td id="L608" class="blob-num js-line-number" data-line-number="608"></td>
        <td id="LC608" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Sha256</span> []<span class="pl-k">byte</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,1,opt,name=sha256,proto3&quot; json:&quot;sha256,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L609" class="blob-num js-line-number" data-line-number="609"></td>
        <td id="LC609" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L610" class="blob-num js-line-number" data-line-number="610"></td>
        <td id="LC610" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L611" class="blob-num js-line-number" data-line-number="611"></td>
        <td id="LC611" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">Checksum</span>) <span class="pl-en">Reset</span></span>()                    { *m = Checksum{} }</td>
      </tr>
      <tr>
        <td id="L612" class="blob-num js-line-number" data-line-number="612"></td>
        <td id="LC612" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">Checksum</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L613" class="blob-num js-line-number" data-line-number="613"></td>
        <td id="LC613" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">Checksum</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L614" class="blob-num js-line-number" data-line-number="614"></td>
        <td id="LC614" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">Checksum</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">9</span>} }</td>
      </tr>
      <tr>
        <td id="L615" class="blob-num js-line-number" data-line-number="615"></td>
        <td id="LC615" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L616" class="blob-num js-line-number" data-line-number="616"></td>
        <td id="LC616" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> An individual threat; for example, a malicious URL or its hash</span></td>
      </tr>
      <tr>
        <td id="L617" class="blob-num js-line-number" data-line-number="617"></td>
        <td id="LC617" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> representation. Only one of these fields should be set.</span></td>
      </tr>
      <tr>
        <td id="L618" class="blob-num js-line-number" data-line-number="618"></td>
        <td id="LC618" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">ThreatEntry</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L619" class="blob-num js-line-number" data-line-number="619"></td>
        <td id="LC619" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> A hash prefix, consisting of the most significant 4-32 bytes of a SHA256</span></td>
      </tr>
      <tr>
        <td id="L620" class="blob-num js-line-number" data-line-number="620"></td>
        <td id="LC620" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> hash.</span></td>
      </tr>
      <tr>
        <td id="L621" class="blob-num js-line-number" data-line-number="621"></td>
        <td id="LC621" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Hash</span> []<span class="pl-k">byte</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,1,opt,name=hash,proto3&quot; json:&quot;hash,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L622" class="blob-num js-line-number" data-line-number="622"></td>
        <td id="LC622" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> A URL.</span></td>
      </tr>
      <tr>
        <td id="L623" class="blob-num js-line-number" data-line-number="623"></td>
        <td id="LC623" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Url</span> <span class="pl-k">string</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,2,opt,name=url&quot; json:&quot;url,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L624" class="blob-num js-line-number" data-line-number="624"></td>
        <td id="LC624" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L625" class="blob-num js-line-number" data-line-number="625"></td>
        <td id="LC625" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L626" class="blob-num js-line-number" data-line-number="626"></td>
        <td id="LC626" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatEntry</span>) <span class="pl-en">Reset</span></span>()                    { *m = ThreatEntry{} }</td>
      </tr>
      <tr>
        <td id="L627" class="blob-num js-line-number" data-line-number="627"></td>
        <td id="LC627" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatEntry</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L628" class="blob-num js-line-number" data-line-number="628"></td>
        <td id="LC628" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ThreatEntry</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L629" class="blob-num js-line-number" data-line-number="629"></td>
        <td id="LC629" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ThreatEntry</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">10</span>} }</td>
      </tr>
      <tr>
        <td id="L630" class="blob-num js-line-number" data-line-number="630"></td>
        <td id="LC630" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L631" class="blob-num js-line-number" data-line-number="631"></td>
        <td id="LC631" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> A set of threats that should be added or removed from a client&#39;s local</span></td>
      </tr>
      <tr>
        <td id="L632" class="blob-num js-line-number" data-line-number="632"></td>
        <td id="LC632" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> database.</span></td>
      </tr>
      <tr>
        <td id="L633" class="blob-num js-line-number" data-line-number="633"></td>
        <td id="LC633" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">ThreatEntrySet</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L634" class="blob-num js-line-number" data-line-number="634"></td>
        <td id="LC634" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The compression type for the entries in this set.</span></td>
      </tr>
      <tr>
        <td id="L635" class="blob-num js-line-number" data-line-number="635"></td>
        <td id="LC635" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">CompressionType</span> <span class="pl-v">CompressionType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,1,opt,name=compression_type,json=compressionType,enum=safebrowsing_proto.CompressionType&quot; json:&quot;compression_type,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L636" class="blob-num js-line-number" data-line-number="636"></td>
        <td id="LC636" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The raw SHA256-formatted entries.</span></td>
      </tr>
      <tr>
        <td id="L637" class="blob-num js-line-number" data-line-number="637"></td>
        <td id="LC637" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">RawHashes</span> *RawHashes <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,2,opt,name=raw_hashes,json=rawHashes&quot; json:&quot;raw_hashes,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L638" class="blob-num js-line-number" data-line-number="638"></td>
        <td id="LC638" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The raw removal indices for a local list.</span></td>
      </tr>
      <tr>
        <td id="L639" class="blob-num js-line-number" data-line-number="639"></td>
        <td id="LC639" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">RawIndices</span> *RawIndices <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,3,opt,name=raw_indices,json=rawIndices&quot; json:&quot;raw_indices,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L640" class="blob-num js-line-number" data-line-number="640"></td>
        <td id="LC640" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The encoded 4-byte prefixes of SHA256-formatted entries, using a</span></td>
      </tr>
      <tr>
        <td id="L641" class="blob-num js-line-number" data-line-number="641"></td>
        <td id="LC641" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Golomb-Rice encoding.</span></td>
      </tr>
      <tr>
        <td id="L642" class="blob-num js-line-number" data-line-number="642"></td>
        <td id="LC642" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">RiceHashes</span> *RiceDeltaEncoding <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,4,opt,name=rice_hashes,json=riceHashes&quot; json:&quot;rice_hashes,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L643" class="blob-num js-line-number" data-line-number="643"></td>
        <td id="LC643" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The encoded local, lexicographically-sorted list indices, using a</span></td>
      </tr>
      <tr>
        <td id="L644" class="blob-num js-line-number" data-line-number="644"></td>
        <td id="LC644" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Golomb-Rice encoding. Used for sending compressed removal indices.</span></td>
      </tr>
      <tr>
        <td id="L645" class="blob-num js-line-number" data-line-number="645"></td>
        <td id="LC645" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">RiceIndices</span> *RiceDeltaEncoding <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,5,opt,name=rice_indices,json=riceIndices&quot; json:&quot;rice_indices,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L646" class="blob-num js-line-number" data-line-number="646"></td>
        <td id="LC646" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L647" class="blob-num js-line-number" data-line-number="647"></td>
        <td id="LC647" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L648" class="blob-num js-line-number" data-line-number="648"></td>
        <td id="LC648" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatEntrySet</span>) <span class="pl-en">Reset</span></span>()                    { *m = ThreatEntrySet{} }</td>
      </tr>
      <tr>
        <td id="L649" class="blob-num js-line-number" data-line-number="649"></td>
        <td id="LC649" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatEntrySet</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L650" class="blob-num js-line-number" data-line-number="650"></td>
        <td id="LC650" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ThreatEntrySet</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L651" class="blob-num js-line-number" data-line-number="651"></td>
        <td id="LC651" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ThreatEntrySet</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">11</span>} }</td>
      </tr>
      <tr>
        <td id="L652" class="blob-num js-line-number" data-line-number="652"></td>
        <td id="LC652" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L653" class="blob-num js-line-number" data-line-number="653"></td>
        <td id="LC653" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatEntrySet</span>) <span class="pl-en">GetRawHashes</span></span>() *<span class="pl-v">RawHashes</span> {</td>
      </tr>
      <tr>
        <td id="L654" class="blob-num js-line-number" data-line-number="654"></td>
        <td id="LC654" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L655" class="blob-num js-line-number" data-line-number="655"></td>
        <td id="LC655" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">RawHashes</span></td>
      </tr>
      <tr>
        <td id="L656" class="blob-num js-line-number" data-line-number="656"></td>
        <td id="LC656" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L657" class="blob-num js-line-number" data-line-number="657"></td>
        <td id="LC657" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L658" class="blob-num js-line-number" data-line-number="658"></td>
        <td id="LC658" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L659" class="blob-num js-line-number" data-line-number="659"></td>
        <td id="LC659" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L660" class="blob-num js-line-number" data-line-number="660"></td>
        <td id="LC660" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatEntrySet</span>) <span class="pl-en">GetRawIndices</span></span>() *<span class="pl-v">RawIndices</span> {</td>
      </tr>
      <tr>
        <td id="L661" class="blob-num js-line-number" data-line-number="661"></td>
        <td id="LC661" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L662" class="blob-num js-line-number" data-line-number="662"></td>
        <td id="LC662" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">RawIndices</span></td>
      </tr>
      <tr>
        <td id="L663" class="blob-num js-line-number" data-line-number="663"></td>
        <td id="LC663" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L664" class="blob-num js-line-number" data-line-number="664"></td>
        <td id="LC664" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L665" class="blob-num js-line-number" data-line-number="665"></td>
        <td id="LC665" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L666" class="blob-num js-line-number" data-line-number="666"></td>
        <td id="LC666" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L667" class="blob-num js-line-number" data-line-number="667"></td>
        <td id="LC667" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatEntrySet</span>) <span class="pl-en">GetRiceHashes</span></span>() *<span class="pl-v">RiceDeltaEncoding</span> {</td>
      </tr>
      <tr>
        <td id="L668" class="blob-num js-line-number" data-line-number="668"></td>
        <td id="LC668" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L669" class="blob-num js-line-number" data-line-number="669"></td>
        <td id="LC669" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">RiceHashes</span></td>
      </tr>
      <tr>
        <td id="L670" class="blob-num js-line-number" data-line-number="670"></td>
        <td id="LC670" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L671" class="blob-num js-line-number" data-line-number="671"></td>
        <td id="LC671" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L672" class="blob-num js-line-number" data-line-number="672"></td>
        <td id="LC672" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L673" class="blob-num js-line-number" data-line-number="673"></td>
        <td id="LC673" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L674" class="blob-num js-line-number" data-line-number="674"></td>
        <td id="LC674" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatEntrySet</span>) <span class="pl-en">GetRiceIndices</span></span>() *<span class="pl-v">RiceDeltaEncoding</span> {</td>
      </tr>
      <tr>
        <td id="L675" class="blob-num js-line-number" data-line-number="675"></td>
        <td id="LC675" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L676" class="blob-num js-line-number" data-line-number="676"></td>
        <td id="LC676" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">RiceIndices</span></td>
      </tr>
      <tr>
        <td id="L677" class="blob-num js-line-number" data-line-number="677"></td>
        <td id="LC677" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L678" class="blob-num js-line-number" data-line-number="678"></td>
        <td id="LC678" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L679" class="blob-num js-line-number" data-line-number="679"></td>
        <td id="LC679" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L680" class="blob-num js-line-number" data-line-number="680"></td>
        <td id="LC680" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L681" class="blob-num js-line-number" data-line-number="681"></td>
        <td id="LC681" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> A set of raw indices to remove from a local list.</span></td>
      </tr>
      <tr>
        <td id="L682" class="blob-num js-line-number" data-line-number="682"></td>
        <td id="LC682" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">RawIndices</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L683" class="blob-num js-line-number" data-line-number="683"></td>
        <td id="LC683" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The indices to remove from a lexicographically-sorted local list.</span></td>
      </tr>
      <tr>
        <td id="L684" class="blob-num js-line-number" data-line-number="684"></td>
        <td id="LC684" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Indices</span> []<span class="pl-k">int32</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,1,rep,name=indices&quot; json:&quot;indices,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L685" class="blob-num js-line-number" data-line-number="685"></td>
        <td id="LC685" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L686" class="blob-num js-line-number" data-line-number="686"></td>
        <td id="LC686" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L687" class="blob-num js-line-number" data-line-number="687"></td>
        <td id="LC687" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">RawIndices</span>) <span class="pl-en">Reset</span></span>()                    { *m = RawIndices{} }</td>
      </tr>
      <tr>
        <td id="L688" class="blob-num js-line-number" data-line-number="688"></td>
        <td id="LC688" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">RawIndices</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L689" class="blob-num js-line-number" data-line-number="689"></td>
        <td id="LC689" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">RawIndices</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L690" class="blob-num js-line-number" data-line-number="690"></td>
        <td id="LC690" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">RawIndices</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">12</span>} }</td>
      </tr>
      <tr>
        <td id="L691" class="blob-num js-line-number" data-line-number="691"></td>
        <td id="LC691" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L692" class="blob-num js-line-number" data-line-number="692"></td>
        <td id="LC692" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> The uncompressed threat entries in hash format of a particular prefix length.</span></td>
      </tr>
      <tr>
        <td id="L693" class="blob-num js-line-number" data-line-number="693"></td>
        <td id="LC693" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> Hashes can be anywhere from 4 to 32 bytes in size. A large majority are 4</span></td>
      </tr>
      <tr>
        <td id="L694" class="blob-num js-line-number" data-line-number="694"></td>
        <td id="LC694" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> bytes, but some hashes are lengthened if they collide with the hash of a</span></td>
      </tr>
      <tr>
        <td id="L695" class="blob-num js-line-number" data-line-number="695"></td>
        <td id="LC695" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> popular URL.</span></td>
      </tr>
      <tr>
        <td id="L696" class="blob-num js-line-number" data-line-number="696"></td>
        <td id="LC696" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span></span></td>
      </tr>
      <tr>
        <td id="L697" class="blob-num js-line-number" data-line-number="697"></td>
        <td id="LC697" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> Used for sending ThreatEntrySet to clients that do not support compression,</span></td>
      </tr>
      <tr>
        <td id="L698" class="blob-num js-line-number" data-line-number="698"></td>
        <td id="LC698" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> or when sending non-4-byte hashes to clients that do support compression.</span></td>
      </tr>
      <tr>
        <td id="L699" class="blob-num js-line-number" data-line-number="699"></td>
        <td id="LC699" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">RawHashes</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L700" class="blob-num js-line-number" data-line-number="700"></td>
        <td id="LC700" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The number of bytes for each prefix encoded below.  This field can be</span></td>
      </tr>
      <tr>
        <td id="L701" class="blob-num js-line-number" data-line-number="701"></td>
        <td id="LC701" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> anywhere from 4 (shortest prefix) to 32 (full SHA256 hash).</span></td>
      </tr>
      <tr>
        <td id="L702" class="blob-num js-line-number" data-line-number="702"></td>
        <td id="LC702" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">PrefixSize</span> <span class="pl-k">int32</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,1,opt,name=prefix_size,json=prefixSize&quot; json:&quot;prefix_size,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L703" class="blob-num js-line-number" data-line-number="703"></td>
        <td id="LC703" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The hashes, all concatenated into one long string.  Each hash has a prefix</span></td>
      </tr>
      <tr>
        <td id="L704" class="blob-num js-line-number" data-line-number="704"></td>
        <td id="LC704" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> size of |prefix_size| above. Hashes are sorted in lexicographic order.</span></td>
      </tr>
      <tr>
        <td id="L705" class="blob-num js-line-number" data-line-number="705"></td>
        <td id="LC705" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">RawHashes</span> []<span class="pl-k">byte</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,2,opt,name=raw_hashes,json=rawHashes,proto3&quot; json:&quot;raw_hashes,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L706" class="blob-num js-line-number" data-line-number="706"></td>
        <td id="LC706" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L707" class="blob-num js-line-number" data-line-number="707"></td>
        <td id="LC707" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L708" class="blob-num js-line-number" data-line-number="708"></td>
        <td id="LC708" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">RawHashes</span>) <span class="pl-en">Reset</span></span>()                    { *m = RawHashes{} }</td>
      </tr>
      <tr>
        <td id="L709" class="blob-num js-line-number" data-line-number="709"></td>
        <td id="LC709" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">RawHashes</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L710" class="blob-num js-line-number" data-line-number="710"></td>
        <td id="LC710" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">RawHashes</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L711" class="blob-num js-line-number" data-line-number="711"></td>
        <td id="LC711" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">RawHashes</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">13</span>} }</td>
      </tr>
      <tr>
        <td id="L712" class="blob-num js-line-number" data-line-number="712"></td>
        <td id="LC712" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L713" class="blob-num js-line-number" data-line-number="713"></td>
        <td id="LC713" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> The Rice-Golomb encoded data. Used for sending compressed 4-byte hashes or</span></td>
      </tr>
      <tr>
        <td id="L714" class="blob-num js-line-number" data-line-number="714"></td>
        <td id="LC714" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> compressed removal indices.</span></td>
      </tr>
      <tr>
        <td id="L715" class="blob-num js-line-number" data-line-number="715"></td>
        <td id="LC715" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">RiceDeltaEncoding</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L716" class="blob-num js-line-number" data-line-number="716"></td>
        <td id="LC716" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The offset of the first entry in the encoded data, or, if only a single</span></td>
      </tr>
      <tr>
        <td id="L717" class="blob-num js-line-number" data-line-number="717"></td>
        <td id="LC717" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> integer was encoded, that single integer&#39;s value.</span></td>
      </tr>
      <tr>
        <td id="L718" class="blob-num js-line-number" data-line-number="718"></td>
        <td id="LC718" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">FirstValue</span> <span class="pl-k">int64</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,1,opt,name=first_value,json=firstValue&quot; json:&quot;first_value,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L719" class="blob-num js-line-number" data-line-number="719"></td>
        <td id="LC719" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The Golomb-Rice parameter which is a number between 2 and 28. This field</span></td>
      </tr>
      <tr>
        <td id="L720" class="blob-num js-line-number" data-line-number="720"></td>
        <td id="LC720" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> is missing (that is, zero) if num_entries is zero.</span></td>
      </tr>
      <tr>
        <td id="L721" class="blob-num js-line-number" data-line-number="721"></td>
        <td id="LC721" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">RiceParameter</span> <span class="pl-k">int32</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,2,opt,name=rice_parameter,json=riceParameter&quot; json:&quot;rice_parameter,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L722" class="blob-num js-line-number" data-line-number="722"></td>
        <td id="LC722" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The number of entries that are delta encoded in the encoded data. If only a</span></td>
      </tr>
      <tr>
        <td id="L723" class="blob-num js-line-number" data-line-number="723"></td>
        <td id="LC723" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> single integer was encoded, this will be zero and the single value will be</span></td>
      </tr>
      <tr>
        <td id="L724" class="blob-num js-line-number" data-line-number="724"></td>
        <td id="LC724" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> stored in first_value.</span></td>
      </tr>
      <tr>
        <td id="L725" class="blob-num js-line-number" data-line-number="725"></td>
        <td id="LC725" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">NumEntries</span> <span class="pl-k">int32</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,3,opt,name=num_entries,json=numEntries&quot; json:&quot;num_entries,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L726" class="blob-num js-line-number" data-line-number="726"></td>
        <td id="LC726" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The encoded deltas that are encoded using the Golomb-Rice coder.</span></td>
      </tr>
      <tr>
        <td id="L727" class="blob-num js-line-number" data-line-number="727"></td>
        <td id="LC727" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">EncodedData</span> []<span class="pl-k">byte</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,4,opt,name=encoded_data,json=encodedData,proto3&quot; json:&quot;encoded_data,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L728" class="blob-num js-line-number" data-line-number="728"></td>
        <td id="LC728" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L729" class="blob-num js-line-number" data-line-number="729"></td>
        <td id="LC729" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L730" class="blob-num js-line-number" data-line-number="730"></td>
        <td id="LC730" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">RiceDeltaEncoding</span>) <span class="pl-en">Reset</span></span>()                    { *m = RiceDeltaEncoding{} }</td>
      </tr>
      <tr>
        <td id="L731" class="blob-num js-line-number" data-line-number="731"></td>
        <td id="LC731" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">RiceDeltaEncoding</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L732" class="blob-num js-line-number" data-line-number="732"></td>
        <td id="LC732" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">RiceDeltaEncoding</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L733" class="blob-num js-line-number" data-line-number="733"></td>
        <td id="LC733" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">RiceDeltaEncoding</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">14</span>} }</td>
      </tr>
      <tr>
        <td id="L734" class="blob-num js-line-number" data-line-number="734"></td>
        <td id="LC734" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L735" class="blob-num js-line-number" data-line-number="735"></td>
        <td id="LC735" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> The metadata associated with a specific threat entry. The client is expected</span></td>
      </tr>
      <tr>
        <td id="L736" class="blob-num js-line-number" data-line-number="736"></td>
        <td id="LC736" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> to know the metadata key/value pairs associated with each threat type.</span></td>
      </tr>
      <tr>
        <td id="L737" class="blob-num js-line-number" data-line-number="737"></td>
        <td id="LC737" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">ThreatEntryMetadata</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L738" class="blob-num js-line-number" data-line-number="738"></td>
        <td id="LC738" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The metadata entries.</span></td>
      </tr>
      <tr>
        <td id="L739" class="blob-num js-line-number" data-line-number="739"></td>
        <td id="LC739" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Entries</span> []*ThreatEntryMetadata_MetadataEntry <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,1,rep,name=entries&quot; json:&quot;entries,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L740" class="blob-num js-line-number" data-line-number="740"></td>
        <td id="LC740" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L741" class="blob-num js-line-number" data-line-number="741"></td>
        <td id="LC741" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L742" class="blob-num js-line-number" data-line-number="742"></td>
        <td id="LC742" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatEntryMetadata</span>) <span class="pl-en">Reset</span></span>()                    { *m = ThreatEntryMetadata{} }</td>
      </tr>
      <tr>
        <td id="L743" class="blob-num js-line-number" data-line-number="743"></td>
        <td id="LC743" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatEntryMetadata</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L744" class="blob-num js-line-number" data-line-number="744"></td>
        <td id="LC744" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ThreatEntryMetadata</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L745" class="blob-num js-line-number" data-line-number="745"></td>
        <td id="LC745" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ThreatEntryMetadata</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">15</span>} }</td>
      </tr>
      <tr>
        <td id="L746" class="blob-num js-line-number" data-line-number="746"></td>
        <td id="LC746" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L747" class="blob-num js-line-number" data-line-number="747"></td>
        <td id="LC747" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatEntryMetadata</span>) <span class="pl-en">GetEntries</span></span>() []*<span class="pl-v">ThreatEntryMetadata_MetadataEntry</span> {</td>
      </tr>
      <tr>
        <td id="L748" class="blob-num js-line-number" data-line-number="748"></td>
        <td id="LC748" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L749" class="blob-num js-line-number" data-line-number="749"></td>
        <td id="LC749" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">Entries</span></td>
      </tr>
      <tr>
        <td id="L750" class="blob-num js-line-number" data-line-number="750"></td>
        <td id="LC750" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L751" class="blob-num js-line-number" data-line-number="751"></td>
        <td id="LC751" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L752" class="blob-num js-line-number" data-line-number="752"></td>
        <td id="LC752" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L753" class="blob-num js-line-number" data-line-number="753"></td>
        <td id="LC753" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L754" class="blob-num js-line-number" data-line-number="754"></td>
        <td id="LC754" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> A single metadata entry.</span></td>
      </tr>
      <tr>
        <td id="L755" class="blob-num js-line-number" data-line-number="755"></td>
        <td id="LC755" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">ThreatEntryMetadata_MetadataEntry</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L756" class="blob-num js-line-number" data-line-number="756"></td>
        <td id="LC756" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The metadata entry key.</span></td>
      </tr>
      <tr>
        <td id="L757" class="blob-num js-line-number" data-line-number="757"></td>
        <td id="LC757" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Key</span> []<span class="pl-k">byte</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,1,opt,name=key,proto3&quot; json:&quot;key,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L758" class="blob-num js-line-number" data-line-number="758"></td>
        <td id="LC758" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The metadata entry value.</span></td>
      </tr>
      <tr>
        <td id="L759" class="blob-num js-line-number" data-line-number="759"></td>
        <td id="LC759" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Value</span> []<span class="pl-k">byte</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,2,opt,name=value,proto3&quot; json:&quot;value,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L760" class="blob-num js-line-number" data-line-number="760"></td>
        <td id="LC760" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L761" class="blob-num js-line-number" data-line-number="761"></td>
        <td id="LC761" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L762" class="blob-num js-line-number" data-line-number="762"></td>
        <td id="LC762" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatEntryMetadata_MetadataEntry</span>) <span class="pl-en">Reset</span></span>()         { *m = ThreatEntryMetadata_MetadataEntry{} }</td>
      </tr>
      <tr>
        <td id="L763" class="blob-num js-line-number" data-line-number="763"></td>
        <td id="LC763" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatEntryMetadata_MetadataEntry</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span> { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L764" class="blob-num js-line-number" data-line-number="764"></td>
        <td id="LC764" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ThreatEntryMetadata_MetadataEntry</span>) <span class="pl-en">ProtoMessage</span></span>()    {}</td>
      </tr>
      <tr>
        <td id="L765" class="blob-num js-line-number" data-line-number="765"></td>
        <td id="LC765" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ThreatEntryMetadata_MetadataEntry</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) {</td>
      </tr>
      <tr>
        <td id="L766" class="blob-num js-line-number" data-line-number="766"></td>
        <td id="LC766" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">15</span>, <span class="pl-c1">0</span>}</td>
      </tr>
      <tr>
        <td id="L767" class="blob-num js-line-number" data-line-number="767"></td>
        <td id="LC767" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L768" class="blob-num js-line-number" data-line-number="768"></td>
        <td id="LC768" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L769" class="blob-num js-line-number" data-line-number="769"></td>
        <td id="LC769" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> Describes an individual threat list. A list is defined by three parameters:</span></td>
      </tr>
      <tr>
        <td id="L770" class="blob-num js-line-number" data-line-number="770"></td>
        <td id="LC770" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> the type of threat posed, the type of platform targeted by the threat, and</span></td>
      </tr>
      <tr>
        <td id="L771" class="blob-num js-line-number" data-line-number="771"></td>
        <td id="LC771" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> the type of entries in the list.</span></td>
      </tr>
      <tr>
        <td id="L772" class="blob-num js-line-number" data-line-number="772"></td>
        <td id="LC772" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">ThreatListDescriptor</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L773" class="blob-num js-line-number" data-line-number="773"></td>
        <td id="LC773" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The threat type posed by the list&#39;s entries.</span></td>
      </tr>
      <tr>
        <td id="L774" class="blob-num js-line-number" data-line-number="774"></td>
        <td id="LC774" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatType</span> <span class="pl-v">ThreatType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,1,opt,name=threat_type,json=threatType,enum=safebrowsing_proto.ThreatType&quot; json:&quot;threat_type,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L775" class="blob-num js-line-number" data-line-number="775"></td>
        <td id="LC775" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The platform type targeted by the list&#39;s entries.</span></td>
      </tr>
      <tr>
        <td id="L776" class="blob-num js-line-number" data-line-number="776"></td>
        <td id="LC776" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">PlatformType</span> <span class="pl-v">PlatformType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,2,opt,name=platform_type,json=platformType,enum=safebrowsing_proto.PlatformType&quot; json:&quot;platform_type,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L777" class="blob-num js-line-number" data-line-number="777"></td>
        <td id="LC777" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The entry types contained in the list.</span></td>
      </tr>
      <tr>
        <td id="L778" class="blob-num js-line-number" data-line-number="778"></td>
        <td id="LC778" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatEntryType</span> <span class="pl-v">ThreatEntryType</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,3,opt,name=threat_entry_type,json=threatEntryType,enum=safebrowsing_proto.ThreatEntryType&quot; json:&quot;threat_entry_type,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L779" class="blob-num js-line-number" data-line-number="779"></td>
        <td id="LC779" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L780" class="blob-num js-line-number" data-line-number="780"></td>
        <td id="LC780" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L781" class="blob-num js-line-number" data-line-number="781"></td>
        <td id="LC781" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatListDescriptor</span>) <span class="pl-en">Reset</span></span>()                    { *m = ThreatListDescriptor{} }</td>
      </tr>
      <tr>
        <td id="L782" class="blob-num js-line-number" data-line-number="782"></td>
        <td id="LC782" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ThreatListDescriptor</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L783" class="blob-num js-line-number" data-line-number="783"></td>
        <td id="LC783" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ThreatListDescriptor</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L784" class="blob-num js-line-number" data-line-number="784"></td>
        <td id="LC784" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ThreatListDescriptor</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">16</span>} }</td>
      </tr>
      <tr>
        <td id="L785" class="blob-num js-line-number" data-line-number="785"></td>
        <td id="LC785" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L786" class="blob-num js-line-number" data-line-number="786"></td>
        <td id="LC786" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> A collection of lists available for download by the client.</span></td>
      </tr>
      <tr>
        <td id="L787" class="blob-num js-line-number" data-line-number="787"></td>
        <td id="LC787" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">ListThreatListsResponse</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L788" class="blob-num js-line-number" data-line-number="788"></td>
        <td id="LC788" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> The lists available for download by the client.</span></td>
      </tr>
      <tr>
        <td id="L789" class="blob-num js-line-number" data-line-number="789"></td>
        <td id="LC789" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">ThreatLists</span> []*ThreatListDescriptor <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;bytes,1,rep,name=threat_lists,json=threatLists&quot; json:&quot;threat_lists,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L790" class="blob-num js-line-number" data-line-number="790"></td>
        <td id="LC790" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L791" class="blob-num js-line-number" data-line-number="791"></td>
        <td id="LC791" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L792" class="blob-num js-line-number" data-line-number="792"></td>
        <td id="LC792" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ListThreatListsResponse</span>) <span class="pl-en">Reset</span></span>()                    { *m = ListThreatListsResponse{} }</td>
      </tr>
      <tr>
        <td id="L793" class="blob-num js-line-number" data-line-number="793"></td>
        <td id="LC793" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ListThreatListsResponse</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L794" class="blob-num js-line-number" data-line-number="794"></td>
        <td id="LC794" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ListThreatListsResponse</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L795" class="blob-num js-line-number" data-line-number="795"></td>
        <td id="LC795" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">ListThreatListsResponse</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">17</span>} }</td>
      </tr>
      <tr>
        <td id="L796" class="blob-num js-line-number" data-line-number="796"></td>
        <td id="LC796" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L797" class="blob-num js-line-number" data-line-number="797"></td>
        <td id="LC797" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">ListThreatListsResponse</span>) <span class="pl-en">GetThreatLists</span></span>() []*<span class="pl-v">ThreatListDescriptor</span> {</td>
      </tr>
      <tr>
        <td id="L798" class="blob-num js-line-number" data-line-number="798"></td>
        <td id="LC798" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">if</span> m != <span class="pl-c1">nil</span> {</td>
      </tr>
      <tr>
        <td id="L799" class="blob-num js-line-number" data-line-number="799"></td>
        <td id="LC799" class="blob-code blob-code-inner js-file-line">		<span class="pl-k">return</span> m.<span class="pl-smi">ThreatLists</span></td>
      </tr>
      <tr>
        <td id="L800" class="blob-num js-line-number" data-line-number="800"></td>
        <td id="LC800" class="blob-code blob-code-inner js-file-line">	}</td>
      </tr>
      <tr>
        <td id="L801" class="blob-num js-line-number" data-line-number="801"></td>
        <td id="LC801" class="blob-code blob-code-inner js-file-line">	<span class="pl-k">return</span> <span class="pl-c1">nil</span></td>
      </tr>
      <tr>
        <td id="L802" class="blob-num js-line-number" data-line-number="802"></td>
        <td id="LC802" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L803" class="blob-num js-line-number" data-line-number="803"></td>
        <td id="LC803" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L804" class="blob-num js-line-number" data-line-number="804"></td>
        <td id="LC804" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> A Duration represents a signed, fixed-length span of time represented</span></td>
      </tr>
      <tr>
        <td id="L805" class="blob-num js-line-number" data-line-number="805"></td>
        <td id="LC805" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> as a count of seconds and fractions of seconds at nanosecond</span></td>
      </tr>
      <tr>
        <td id="L806" class="blob-num js-line-number" data-line-number="806"></td>
        <td id="LC806" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> resolution. It is independent of any calendar and concepts like &quot;day&quot;</span></td>
      </tr>
      <tr>
        <td id="L807" class="blob-num js-line-number" data-line-number="807"></td>
        <td id="LC807" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> or &quot;month&quot;. It is related to Timestamp in that the difference between</span></td>
      </tr>
      <tr>
        <td id="L808" class="blob-num js-line-number" data-line-number="808"></td>
        <td id="LC808" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> two Timestamp values is a Duration and it can be added or subtracted</span></td>
      </tr>
      <tr>
        <td id="L809" class="blob-num js-line-number" data-line-number="809"></td>
        <td id="LC809" class="blob-code blob-code-inner js-file-line"><span class="pl-c"><span class="pl-c">//</span> from a Timestamp. Range is approximately +-10,000 years.</span></td>
      </tr>
      <tr>
        <td id="L810" class="blob-num js-line-number" data-line-number="810"></td>
        <td id="LC810" class="blob-code blob-code-inner js-file-line"><span class="pl-k">type</span> <span class="pl-v">Duration</span> <span class="pl-k">struct</span> {</td>
      </tr>
      <tr>
        <td id="L811" class="blob-num js-line-number" data-line-number="811"></td>
        <td id="LC811" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Signed seconds of the span of time. Must be from -315,576,000,000</span></td>
      </tr>
      <tr>
        <td id="L812" class="blob-num js-line-number" data-line-number="812"></td>
        <td id="LC812" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> to +315,576,000,000 inclusive.</span></td>
      </tr>
      <tr>
        <td id="L813" class="blob-num js-line-number" data-line-number="813"></td>
        <td id="LC813" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Seconds</span> <span class="pl-k">int64</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,1,opt,name=seconds&quot; json:&quot;seconds,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L814" class="blob-num js-line-number" data-line-number="814"></td>
        <td id="LC814" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> Signed fractions of a second at nanosecond resolution of the span</span></td>
      </tr>
      <tr>
        <td id="L815" class="blob-num js-line-number" data-line-number="815"></td>
        <td id="LC815" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> of time. Durations less than one second are represented with a 0</span></td>
      </tr>
      <tr>
        <td id="L816" class="blob-num js-line-number" data-line-number="816"></td>
        <td id="LC816" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> `seconds` field and a positive or negative `nanos` field. For durations</span></td>
      </tr>
      <tr>
        <td id="L817" class="blob-num js-line-number" data-line-number="817"></td>
        <td id="LC817" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> of one second or more, a non-zero value for the `nanos` field must be</span></td>
      </tr>
      <tr>
        <td id="L818" class="blob-num js-line-number" data-line-number="818"></td>
        <td id="LC818" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> of the same sign as the `seconds` field. Must be from -999,999,999</span></td>
      </tr>
      <tr>
        <td id="L819" class="blob-num js-line-number" data-line-number="819"></td>
        <td id="LC819" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> to +999,999,999 inclusive.</span></td>
      </tr>
      <tr>
        <td id="L820" class="blob-num js-line-number" data-line-number="820"></td>
        <td id="LC820" class="blob-code blob-code-inner js-file-line">	<span class="pl-v">Nanos</span> <span class="pl-k">int32</span> <span class="pl-s"><span class="pl-pds">`</span>protobuf:&quot;varint,2,opt,name=nanos&quot; json:&quot;nanos,omitempty&quot;<span class="pl-pds">`</span></span></td>
      </tr>
      <tr>
        <td id="L821" class="blob-num js-line-number" data-line-number="821"></td>
        <td id="LC821" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L822" class="blob-num js-line-number" data-line-number="822"></td>
        <td id="LC822" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L823" class="blob-num js-line-number" data-line-number="823"></td>
        <td id="LC823" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">Duration</span>) <span class="pl-en">Reset</span></span>()                    { *m = Duration{} }</td>
      </tr>
      <tr>
        <td id="L824" class="blob-num js-line-number" data-line-number="824"></td>
        <td id="LC824" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(<span class="pl-v">m</span> *<span class="pl-v">Duration</span>) <span class="pl-en">String</span></span>() <span class="pl-v">string</span>            { <span class="pl-k">return</span> proto.<span class="pl-c1">CompactTextString</span>(m) }</td>
      </tr>
      <tr>
        <td id="L825" class="blob-num js-line-number" data-line-number="825"></td>
        <td id="LC825" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">Duration</span>) <span class="pl-en">ProtoMessage</span></span>()               {}</td>
      </tr>
      <tr>
        <td id="L826" class="blob-num js-line-number" data-line-number="826"></td>
        <td id="LC826" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">(*<span class="pl-v">Duration</span>) <span class="pl-en">Descriptor</span></span>() ([]<span class="pl-v">byte</span>, []<span class="pl-v">int</span>) { <span class="pl-k">return</span> fileDescriptor0, []<span class="pl-k">int</span>{<span class="pl-c1">18</span>} }</td>
      </tr>
      <tr>
        <td id="L827" class="blob-num js-line-number" data-line-number="827"></td>
        <td id="LC827" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L828" class="blob-num js-line-number" data-line-number="828"></td>
        <td id="LC828" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">init</span>() {</td>
      </tr>
      <tr>
        <td id="L829" class="blob-num js-line-number" data-line-number="829"></td>
        <td id="LC829" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*ThreatInfo)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.ThreatInfo<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L830" class="blob-num js-line-number" data-line-number="830"></td>
        <td id="LC830" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*ThreatMatch)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.ThreatMatch<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L831" class="blob-num js-line-number" data-line-number="831"></td>
        <td id="LC831" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*FindThreatMatchesRequest)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.FindThreatMatchesRequest<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L832" class="blob-num js-line-number" data-line-number="832"></td>
        <td id="LC832" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*FindThreatMatchesResponse)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.FindThreatMatchesResponse<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L833" class="blob-num js-line-number" data-line-number="833"></td>
        <td id="LC833" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*FetchThreatListUpdatesRequest)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.FetchThreatListUpdatesRequest<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L834" class="blob-num js-line-number" data-line-number="834"></td>
        <td id="LC834" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*FetchThreatListUpdatesRequest_ListUpdateRequest)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.FetchThreatListUpdatesRequest.ListUpdateRequest<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L835" class="blob-num js-line-number" data-line-number="835"></td>
        <td id="LC835" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*FetchThreatListUpdatesRequest_ListUpdateRequest_Constraints)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.FetchThreatListUpdatesRequest.ListUpdateRequest.Constraints<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L836" class="blob-num js-line-number" data-line-number="836"></td>
        <td id="LC836" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*FetchThreatListUpdatesResponse)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.FetchThreatListUpdatesResponse<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L837" class="blob-num js-line-number" data-line-number="837"></td>
        <td id="LC837" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*FetchThreatListUpdatesResponse_ListUpdateResponse)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.FetchThreatListUpdatesResponse.ListUpdateResponse<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L838" class="blob-num js-line-number" data-line-number="838"></td>
        <td id="LC838" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*FindFullHashesRequest)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.FindFullHashesRequest<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L839" class="blob-num js-line-number" data-line-number="839"></td>
        <td id="LC839" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*FindFullHashesResponse)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.FindFullHashesResponse<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L840" class="blob-num js-line-number" data-line-number="840"></td>
        <td id="LC840" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*ClientInfo)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.ClientInfo<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L841" class="blob-num js-line-number" data-line-number="841"></td>
        <td id="LC841" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*Checksum)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.Checksum<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L842" class="blob-num js-line-number" data-line-number="842"></td>
        <td id="LC842" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*ThreatEntry)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.ThreatEntry<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L843" class="blob-num js-line-number" data-line-number="843"></td>
        <td id="LC843" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*ThreatEntrySet)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.ThreatEntrySet<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L844" class="blob-num js-line-number" data-line-number="844"></td>
        <td id="LC844" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*RawIndices)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.RawIndices<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L845" class="blob-num js-line-number" data-line-number="845"></td>
        <td id="LC845" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*RawHashes)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.RawHashes<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L846" class="blob-num js-line-number" data-line-number="846"></td>
        <td id="LC846" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*RiceDeltaEncoding)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.RiceDeltaEncoding<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L847" class="blob-num js-line-number" data-line-number="847"></td>
        <td id="LC847" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*ThreatEntryMetadata)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.ThreatEntryMetadata<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L848" class="blob-num js-line-number" data-line-number="848"></td>
        <td id="LC848" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*ThreatEntryMetadata_MetadataEntry)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.ThreatEntryMetadata.MetadataEntry<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L849" class="blob-num js-line-number" data-line-number="849"></td>
        <td id="LC849" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*ThreatListDescriptor)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.ThreatListDescriptor<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L850" class="blob-num js-line-number" data-line-number="850"></td>
        <td id="LC850" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*ListThreatListsResponse)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.ListThreatListsResponse<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L851" class="blob-num js-line-number" data-line-number="851"></td>
        <td id="LC851" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterType</span>((*Duration)(<span class="pl-c1">nil</span>), <span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.Duration<span class="pl-pds">&quot;</span></span>)</td>
      </tr>
      <tr>
        <td id="L852" class="blob-num js-line-number" data-line-number="852"></td>
        <td id="LC852" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterEnum</span>(<span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.ThreatType<span class="pl-pds">&quot;</span></span>, ThreatType_name, ThreatType_value)</td>
      </tr>
      <tr>
        <td id="L853" class="blob-num js-line-number" data-line-number="853"></td>
        <td id="LC853" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterEnum</span>(<span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.PlatformType<span class="pl-pds">&quot;</span></span>, PlatformType_name, PlatformType_value)</td>
      </tr>
      <tr>
        <td id="L854" class="blob-num js-line-number" data-line-number="854"></td>
        <td id="LC854" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterEnum</span>(<span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.CompressionType<span class="pl-pds">&quot;</span></span>, CompressionType_name, CompressionType_value)</td>
      </tr>
      <tr>
        <td id="L855" class="blob-num js-line-number" data-line-number="855"></td>
        <td id="LC855" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterEnum</span>(<span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.ThreatEntryType<span class="pl-pds">&quot;</span></span>, ThreatEntryType_name, ThreatEntryType_value)</td>
      </tr>
      <tr>
        <td id="L856" class="blob-num js-line-number" data-line-number="856"></td>
        <td id="LC856" class="blob-code blob-code-inner js-file-line">	proto.<span class="pl-c1">RegisterEnum</span>(<span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing_proto.FetchThreatListUpdatesResponse_ListUpdateResponse_ResponseType<span class="pl-pds">&quot;</span></span>, FetchThreatListUpdatesResponse_ListUpdateResponse_ResponseType_name, FetchThreatListUpdatesResponse_ListUpdateResponse_ResponseType_value)</td>
      </tr>
      <tr>
        <td id="L857" class="blob-num js-line-number" data-line-number="857"></td>
        <td id="LC857" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L858" class="blob-num js-line-number" data-line-number="858"></td>
        <td id="LC858" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L859" class="blob-num js-line-number" data-line-number="859"></td>
        <td id="LC859" class="blob-code blob-code-inner js-file-line"><span class="pl-k">func</span> <span class="pl-en">init</span>() { proto.<span class="pl-c1">RegisterFile</span>(<span class="pl-s"><span class="pl-pds">&quot;</span>safebrowsing.proto<span class="pl-pds">&quot;</span></span>, fileDescriptor0) }</td>
      </tr>
      <tr>
        <td id="L860" class="blob-num js-line-number" data-line-number="860"></td>
        <td id="LC860" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L861" class="blob-num js-line-number" data-line-number="861"></td>
        <td id="LC861" class="blob-code blob-code-inner js-file-line"><span class="pl-k">var</span> <span class="pl-smi">fileDescriptor0</span> = []<span class="pl-k">byte</span>{</td>
      </tr>
      <tr>
        <td id="L862" class="blob-num js-line-number" data-line-number="862"></td>
        <td id="LC862" class="blob-code blob-code-inner js-file-line">	<span class="pl-c"><span class="pl-c">//</span> 1635 bytes of a gzipped FileDescriptorProto</span></td>
      </tr>
      <tr>
        <td id="L863" class="blob-num js-line-number" data-line-number="863"></td>
        <td id="LC863" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x1f</span>, <span class="pl-c1">0x8b</span>, <span class="pl-c1">0x08</span>, <span class="pl-c1">0x00</span>, <span class="pl-c1">0x00</span>, <span class="pl-c1">0x09</span>, <span class="pl-c1">0x6e</span>, <span class="pl-c1">0x88</span>, <span class="pl-c1">0x02</span>, <span class="pl-c1">0xff</span>, <span class="pl-c1">0xcc</span>, <span class="pl-c1">0x58</span>, <span class="pl-c1">0x4d</span>, <span class="pl-c1">0x8f</span>, <span class="pl-c1">0xdb</span>, <span class="pl-c1">0xc6</span>,</td>
      </tr>
      <tr>
        <td id="L864" class="blob-num js-line-number" data-line-number="864"></td>
        <td id="LC864" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x19</span>, <span class="pl-c1">0x2e</span>, <span class="pl-c1">0x45</span>, <span class="pl-c1">0x7d</span>, <span class="pl-c1">0xbe</span>, <span class="pl-c1">0xfa</span>, <span class="pl-c1">0x58</span>, <span class="pl-c1">0xee</span>, <span class="pl-c1">0xd8</span>, <span class="pl-c1">0x6b</span>, <span class="pl-c1">0x2b</span>, <span class="pl-c1">0x4e</span>, <span class="pl-c1">0x1c</span>, <span class="pl-c1">0x6f</span>, <span class="pl-c1">0x68</span>, <span class="pl-c1">0xa4</span>,</td>
      </tr>
      <tr>
        <td id="L865" class="blob-num js-line-number" data-line-number="865"></td>
        <td id="LC865" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x35</span>, <span class="pl-c1">0x8c</span>, <span class="pl-c1">0x62</span>, <span class="pl-c1">0x51</span>, <span class="pl-c1">0x38</span>, <span class="pl-c1">0x48</span>, <span class="pl-c1">0xd2</span>, <span class="pl-c1">0x16</span>, <span class="pl-c1">0x45</span>, <span class="pl-c1">0x5b</span>, <span class="pl-c1">0x56</span>, <span class="pl-c1">0xa2</span>, <span class="pl-c1">0xbc</span>, <span class="pl-c1">0x44</span>, <span class="pl-c1">0xb4</span>, <span class="pl-c1">0xa4</span>,</td>
      </tr>
      <tr>
        <td id="L866" class="blob-num js-line-number" data-line-number="866"></td>
        <td id="LC866" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x3a</span>, <span class="pl-c1">0x92</span>, <span class="pl-c1">0xbc</span>, <span class="pl-c1">0x76</span>, <span class="pl-c1">0x73</span>, <span class="pl-c1">0x20</span>, <span class="pl-c1">0x68</span>, <span class="pl-c1">0x6a</span>, <span class="pl-c1">0xd6</span>, <span class="pl-c1">0x22</span>, <span class="pl-c1">0x22</span>, <span class="pl-c1">0x91</span>, <span class="pl-c1">0x0a</span>, <span class="pl-c1">0x67</span>, <span class="pl-c1">0x64</span>, <span class="pl-c1">0x79</span>,</td>
      </tr>
      <tr>
        <td id="L867" class="blob-num js-line-number" data-line-number="867"></td>
        <td id="LC867" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xf3</span>, <span class="pl-c1">0x13</span>, <span class="pl-c1">0x7a</span>, <span class="pl-c1">0x2a</span>, <span class="pl-c1">0x50</span>, <span class="pl-c1">0xf4</span>, <span class="pl-c1">0xdc</span>, <span class="pl-c1">0x9e</span>, <span class="pl-c1">0x7b</span>, <span class="pl-c1">0x2d</span>, <span class="pl-c1">0xfa</span>, <span class="pl-c1">0x03</span>, <span class="pl-c1">0xfa</span>, <span class="pl-c1">0x33</span>, <span class="pl-c1">0x7a</span>, <span class="pl-c1">0xec</span>,</td>
      </tr>
      <tr>
        <td id="L868" class="blob-num js-line-number" data-line-number="868"></td>
        <td id="LC868" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x2f</span>, <span class="pl-c1">0x28</span>, <span class="pl-c1">0x7a</span>, <span class="pl-c1">0xee</span>, <span class="pl-c1">0x25</span>, <span class="pl-c1">0x98</span>, <span class="pl-c1">0xe1</span>, <span class="pl-c1">0x50</span>, <span class="pl-c1">0xa2</span>, <span class="pl-c1">0x3e</span>, <span class="pl-c1">0xd6</span>, <span class="pl-c1">0x96</span>, <span class="pl-c1">0xb3</span>, <span class="pl-c1">0x3e</span>, <span class="pl-c1">0xf8</span>, <span class="pl-c1">0x36</span>,</td>
      </tr>
      <tr>
        <td id="L869" class="blob-num js-line-number" data-line-number="869"></td>
        <td id="LC869" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xf3</span>, <span class="pl-c1">0xf2</span>, <span class="pl-c1">0x9d</span>, <span class="pl-c1">0x67</span>, <span class="pl-c1">0x5e</span>, <span class="pl-c1">0x3e</span>, <span class="pl-c1">0xef</span>, <span class="pl-c1">0x27</span>, <span class="pl-c1">0x09</span>, <span class="pl-c1">0x88</span>, <span class="pl-c1">0x7a</span>, <span class="pl-c1">0x17</span>, <span class="pl-c1">0xe4</span>, <span class="pl-c1">0x79</span>, <span class="pl-c1">0x1c</span>, <span class="pl-c1">0x2d</span>,</td>
      </tr>
      <tr>
        <td id="L870" class="blob-num js-line-number" data-line-number="870"></td>
        <td id="LC870" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x68</span>, <span class="pl-c1">0x10</span>, <span class="pl-c1">0xbe</span>, <span class="pl-c1">0x38</span>, <span class="pl-c1">0x99</span>, <span class="pl-c1">0xc5</span>, <span class="pl-c1">0x11</span>, <span class="pl-c1">0x8b</span>, <span class="pl-c1">0xd0</span>, <span class="pl-c1">0x9a</span>, <span class="pl-c1">0xcc</span>, <span class="pl-c1">0x15</span>, <span class="pl-c1">0x32</span>, <span class="pl-c1">0xfd</span>, <span class="pl-c1">0x1f</span>, <span class="pl-c1">0x39</span>,</td>
      </tr>
      <tr>
        <td id="L871" class="blob-num js-line-number" data-line-number="871"></td>
        <td id="LC871" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x80</span>, <span class="pl-c1">0xc1</span>, <span class="pl-c1">0x38</span>, <span class="pl-c1">0x26</span>, <span class="pl-c1">0x1e</span>, <span class="pl-c1">0xb3</span>, <span class="pl-c1">0xc2</span>, <span class="pl-c1">0x8b</span>, <span class="pl-c1">0x08</span>, <span class="pl-c1">0x19</span>, <span class="pl-c1">0x50</span>, <span class="pl-c1">0x63</span>, <span class="pl-c1">0x62</span>, <span class="pl-c1">0xe7</span>, <span class="pl-c1">0xb2</span>, <span class="pl-c1">0xcb</span>,</td>
      </tr>
      <tr>
        <td id="L872" class="blob-num js-line-number" data-line-number="872"></td>
        <td id="LC872" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x19</span>, <span class="pl-c1">0xa1</span>, <span class="pl-c1">0x4d</span>, <span class="pl-c1">0xe5</span>, <span class="pl-c1">0x58</span>, <span class="pl-c1">0x7d</span>, <span class="pl-c1">0xd0</span>, <span class="pl-c1">0x78</span>, <span class="pl-c1">0xf4</span>, <span class="pl-c1">0xf1</span>, <span class="pl-c1">0xc9</span>, <span class="pl-c1">0xf6</span>, <span class="pl-c1">0xc9</span>, <span class="pl-c1">0x93</span>, <span class="pl-c1">0xe4</span>, <span class="pl-c1">0xd4</span>,</td>
      </tr>
      <tr>
        <td id="L873" class="blob-num js-line-number" data-line-number="873"></td>
        <td id="LC873" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xe0</span>, <span class="pl-c1">0x72</span>, <span class="pl-c1">0x46</span>, <span class="pl-c1">0x70</span>, <span class="pl-c1">0x95</span>, <span class="pl-c1">0x2d</span>, <span class="pl-c1">0xd7</span>, <span class="pl-c1">0x14</span>, <span class="pl-c1">0x3d</span>, <span class="pl-c1">0x86</span>, <span class="pl-c1">0xc6</span>, <span class="pl-c1">0x6c</span>, <span class="pl-c1">0xe2</span>, <span class="pl-c1">0xb1</span>, <span class="pl-c1">0x8b</span>, <span class="pl-c1">0x28</span>,</td>
      </tr>
      <tr>
        <td id="L874" class="blob-num js-line-number" data-line-number="874"></td>
        <td id="LC874" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x9e</span>, <span class="pl-c1">0x4a</span>, <span class="pl-c1">0x90</span>, <span class="pl-c1">0x9c</span>, <span class="pl-c1">0x00</span>, <span class="pl-c1">0x39</span>, <span class="pl-c1">0xde</span>, <span class="pl-c1">0x05</span>, <span class="pl-c1">0xd2</span>, <span class="pl-c1">0x93</span>, <span class="pl-c1">0x9a</span>, <span class="pl-c1">0x02</span>, <span class="pl-c1">0xa6</span>, <span class="pl-c1">0x3e</span>, <span class="pl-c1">0xcb</span>, <span class="pl-c1">0xec</span>,</td>
      </tr>
      <tr>
        <td id="L875" class="blob-num js-line-number" data-line-number="875"></td>
        <td id="LC875" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x28</span>, <span class="pl-c1">0xfa</span>, <span class="pl-c1">0x3d</span>, <span class="pl-c1">0x20</span>, <span class="pl-c1">0x69</span>, <span class="pl-c1">0x0b</span>, <span class="pl-c1">0x09</span>, <span class="pl-c1">0x59</span>, <span class="pl-c1">0x7c</span>, <span class="pl-c1">0x29</span>, <span class="pl-c1">0xc1</span>, <span class="pl-c1">0xf2</span>, <span class="pl-c1">0x02</span>, <span class="pl-c1">0xec</span>, <span class="pl-c1">0xfe</span>, <span class="pl-c1">0xd5</span>,</td>
      </tr>
      <tr>
        <td id="L876" class="blob-num js-line-number" data-line-number="876"></td>
        <td id="LC876" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x16</span>, <span class="pl-c1">0x99</span>, <span class="pl-c1">0x5c</span>, <span class="pl-c1">0x59</span>, <span class="pl-c1">0xe0</span>, <span class="pl-c1">0x69</span>, <span class="pl-c1">0x6c</span>, <span class="pl-c1">0x5d</span>, <span class="pl-c1">0x40</span>, <span class="pl-c1">0x51</span>, <span class="pl-c1">0x07</span>, <span class="pl-c1">0x1a</span>, <span class="pl-c1">0x19</span>, <span class="pl-c1">0xc8</span>, <span class="pl-c1">0x80</span>, <span class="pl-c1">0xd0</span>,</td>
      </tr>
      <tr>
        <td id="L877" class="blob-num js-line-number" data-line-number="877"></td>
        <td id="LC877" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xa6</span>, <span class="pl-c1">0x7a</span>, <span class="pl-c1">0xac</span>, <span class="pl-c1">0x3e</span>, <span class="pl-c1">0xa8</span>, <span class="pl-c1">0x3e</span>, <span class="pl-c1">0xba</span>, <span class="pl-c1">0xf7</span>, <span class="pl-c1">0x06</span>, <span class="pl-c1">0x38</span>, <span class="pl-c1">0x5c</span>, <span class="pl-c1">0x5f</span>, <span class="pl-c1">0x41</span>, <span class="pl-c1">0x05</span>, <span class="pl-c1">0x84</span>, <span class="pl-c1">0xea</span>,</td>
      </tr>
      <tr>
        <td id="L878" class="blob-num js-line-number" data-line-number="878"></td>
        <td id="LC878" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xff</span>, <span class="pl-c1">0x52</span>, <span class="pl-c1">0xa1</span>, <span class="pl-c1">0x9a</span>, <span class="pl-c1">0x3c</span>, <span class="pl-c1">0x3e</span>, <span class="pl-c1">0xf3</span>, <span class="pl-c1">0x98</span>, <span class="pl-c1">0x3f</span>, <span class="pl-c1">0x46</span>, <span class="pl-c1">0xbf</span>, <span class="pl-c1">0x81</span>, <span class="pl-c1">0x6a</span>, <span class="pl-c1">0x86</span>, <span class="pl-c1">0xb6</span>, <span class="pl-c1">0xa6</span>,</td>
      </tr>
      <tr>
        <td id="L879" class="blob-num js-line-number" data-line-number="879"></td>
        <td id="LC879" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x72</span>, <span class="pl-c1">0xac</span>, <span class="pl-c1">0xec</span>, <span class="pl-c1">0xc1</span>, <span class="pl-c1">0x1a</span>, <span class="pl-c1">0xac</span>, <span class="pl-c1">0x58</span>, <span class="pl-c1">0x43</span>, <span class="pl-c1">0x26</span>, <span class="pl-c1">0xd4</span>, <span class="pl-c1">0xd7</span>, <span class="pl-c1">0x48</span>, <span class="pl-c1">0x6b</span>, <span class="pl-c1">0xe6</span>, <span class="pl-c1">0x04</span>, <span class="pl-c1">0xc4</span>,</td>
      </tr>
      <tr>
        <td id="L880" class="blob-num js-line-number" data-line-number="880"></td>
        <td id="LC880" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x9b</span>, <span class="pl-c1">0x39</span>, <span class="pl-c1">0xab</span>, <span class="pl-c1">0x65</span>, <span class="pl-c1">0x39</span>, <span class="pl-c1">0x43</span>, <span class="pl-c1">0x0e</span>, <span class="pl-c1">0x1c</span>, <span class="pl-c1">0x6e</span>, <span class="pl-c1">0x51</span>, <span class="pl-c1">0xd6</span>, <span class="pl-c1">0x2c</span>, <span class="pl-c1">0x0a</span>, <span class="pl-c1">0xa8</span>, <span class="pl-c1">0xbd</span>, <span class="pl-c1">0x18</span>,</td>
      </tr>
      <tr>
        <td id="L881" class="blob-num js-line-number" data-line-number="881"></td>
        <td id="LC881" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x3b</span>, <span class="pl-c1">0xd8</span>, <span class="pl-c1">0x60</span>, <span class="pl-c1">0x0c</span>, <span class="pl-c1">0x7d</span>, <span class="pl-c1">0x09</span>, <span class="pl-c1">0xc5</span>, <span class="pl-c1">0x44</span>, <span class="pl-c1">0xd4</span>, <span class="pl-c1">0x54</span>, <span class="pl-c1">0x8f</span>, <span class="pl-c1">0x95</span>, <span class="pl-c1">0x7d</span>, <span class="pl-c1">0x88</span>, <span class="pl-c1">0x92</span>, <span class="pl-c1">0xea</span>,</td>
      </tr>
      <tr>
        <td id="L882" class="blob-num js-line-number" data-line-number="882"></td>
        <td id="LC882" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xe8</span>, <span class="pl-c1">0x6b</span>, <span class="pl-c1">0x38</span>, <span class="pl-c1">0x5a</span>, <span class="pl-c1">0xb3</span>, <span class="pl-c1">0x64</span>, <span class="pl-c1">0x4a</span>, <span class="pl-c1">0x98</span>, <span class="pl-c1">0x37</span>, <span class="pl-c1">0xf2</span>, <span class="pl-c1">0x98</span>, <span class="pl-c1">0xd7</span>, <span class="pl-c1">0xcc</span>, <span class="pl-c1">0x0b</span>, <span class="pl-c1">0x9c</span>, <span class="pl-c1">0x9f</span>,</td>
      </tr>
      <tr>
        <td id="L883" class="blob-num js-line-number" data-line-number="883"></td>
        <td id="LC883" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xbc</span>, <span class="pl-c1">0x01</span>, <span class="pl-c1">0xe7</span>, <span class="pl-c1">0x4c</span>, <span class="pl-c1">0xaa</span>, <span class="pl-c1">0xe3</span>, <span class="pl-c1">0x1b</span>, <span class="pl-c1">0x6c</span>, <span class="pl-c1">0x5b</span>, <span class="pl-c1">0x88</span>, <span class="pl-c1">0x5a</span>, <span class="pl-c1">0xd0</span>, <span class="pl-c1">0xf0</span>, <span class="pl-c1">0x3d</span>, <span class="pl-c1">0x7f</span>, <span class="pl-c1">0x4c</span>,</td>
      </tr>
      <tr>
        <td id="L884" class="blob-num js-line-number" data-line-number="884"></td>
        <td id="LC884" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xdc</span>, <span class="pl-c1">0xd1</span>, <span class="pl-c1">0x3c</span>, <span class="pl-c1">0xf6</span>, <span class="pl-c1">0x58</span>, <span class="pl-c1">0x10</span>, <span class="pl-c1">0x85</span>, <span class="pl-c1">0xcd</span>, <span class="pl-c1">0x82</span>, <span class="pl-c1">0x40</span>, <span class="pl-c1">0xfd</span>, <span class="pl-c1">0x68</span>, <span class="pl-c1">0x17</span>, <span class="pl-c1">0x6a</span>, <span class="pl-c1">0x5b</span>, <span class="pl-c1">0xea</span>,</td>
      </tr>
      <tr>
        <td id="L885" class="blob-num js-line-number" data-line-number="885"></td>
        <td id="LC885" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xe0</span>, <span class="pl-c1">0xba</span>, <span class="pl-c1">0x38</span>, <span class="pl-c1">0x93</span>, <span class="pl-c1">0x6e</span>, <span class="pl-c1">0xf5</span>, <span class="pl-c1">0x3f</span>, <span class="pl-c1">0x2b</span>, <span class="pl-c1">0xd0</span>, <span class="pl-c1">0xec</span>, <span class="pl-c1">0x04</span>, <span class="pl-c1">0xe1</span>, <span class="pl-c1">0x28</span>, <span class="pl-c1">0xe3</span>, <span class="pl-c1">0x47</span>, <span class="pl-c1">0x42</span>,</td>
      </tr>
      <tr>
        <td id="L886" class="blob-num js-line-number" data-line-number="886"></td>
        <td id="LC886" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x31</span>, <span class="pl-c1">0xf9</span>, <span class="pl-c1">0x76</span>, <span class="pl-c1">0x4e</span>, <span class="pl-c1">0x28</span>, <span class="pl-c1">0x43</span>, <span class="pl-c1">0x5f</span>, <span class="pl-c1">0x40</span>, <span class="pl-c1">0xd1</span>, <span class="pl-c1">0x9f</span>, <span class="pl-c1">0x04</span>, <span class="pl-c1">0x24</span>, <span class="pl-c1">0x64</span>, <span class="pl-c1">0xc2</span>, <span class="pl-c1">0x97</span>, <span class="pl-c1">0xd5</span>,</td>
      </tr>
      <tr>
        <td id="L887" class="blob-num js-line-number" data-line-number="887"></td>
        <td id="LC887" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xdd</span>, <span class="pl-c1">0xbe</span>, <span class="pl-c1">0x6c</span>, <span class="pl-c1">0x09</span>, <span class="pl-c1">0x0d</span>, <span class="pl-c1">0x9e</span>, <span class="pl-c1">0x37</span>, <span class="pl-c1">0x58</span>, <span class="pl-c1">0x6a</span>, <span class="pl-c1">0x67</span>, <span class="pl-c1">0x02</span>, <span class="pl-c1">0x21</span>, <span class="pl-c1">0x08</span>, <span class="pl-c1">0x2f</span>, <span class="pl-c1">0x22</span>, <span class="pl-c1">0xe1</span>,</td>
      </tr>
      <tr>
        <td id="L888" class="blob-num js-line-number" data-line-number="888"></td>
        <td id="LC888" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xc5</span>, <span class="pl-c1">0xea</span>, <span class="pl-c1">0xeb</span>, <span class="pl-c1">0x02</span>, <span class="pl-c1">0x41</span>, <span class="pl-c1">0x1c</span>, <span class="pl-c1">0x96</span>, <span class="pl-c1">0x81</span>, <span class="pl-c1">0xc0</span>, <span class="pl-c1">0xd7</span>, <span class="pl-c1">0xfa</span>, <span class="pl-c1">0x13</span>, <span class="pl-c1">0xf8</span>, <span class="pl-c1">0x60</span>, <span class="pl-c1">0x87</span>, <span class="pl-c1">0x51</span>,</td>
      </tr>
      <tr>
        <td id="L889" class="blob-num js-line-number" data-line-number="889"></td>
        <td id="LC889" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x74</span>, <span class="pl-c1">0x16</span>, <span class="pl-c1">0x85</span>, <span class="pl-c1">0x94</span>, <span class="pl-c1">0xa0</span>, <span class="pl-c1">0x5f</span>, <span class="pl-c1">0x40</span>, <span class="pl-c1">0x69</span>, <span class="pl-c1">0x9a</span>, <span class="pl-c1">0x88</span>, <span class="pl-c1">0x44</span>, <span class="pl-c1">0x62</span>, <span class="pl-c1">0xbe</span>, <span class="pl-c1">0xd6</span>, <span class="pl-c1">0x1d</span>, <span class="pl-c1">0xe2</span>,</td>
      </tr>
      <tr>
        <td id="L890" class="blob-num js-line-number" data-line-number="890"></td>
        <td id="LC890" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x2c</span>, <span class="pl-c1">0x4e</span>, <span class="pl-c1">0xf5</span>, <span class="pl-c1">0xf5</span>, <span class="pl-c1">0xbf</span>, <span class="pl-c1">0x17</span>, <span class="pl-c1">0xe1</span>, <span class="pl-c1">0x6e</span>, <span class="pl-c1">0x87</span>, <span class="pl-c1">0x30</span>, <span class="pl-c1">0x7f</span>, <span class="pl-c1">0x9c</span>, <span class="pl-c1">0x3c</span>, <span class="pl-c1">0xed</span>, <span class="pl-c1">0x06</span>, <span class="pl-c1">0x94</span>,</td>
      </tr>
      <tr>
        <td id="L891" class="blob-num js-line-number" data-line-number="891"></td>
        <td id="LC891" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x0d</span>, <span class="pl-c1">0x67</span>, <span class="pl-c1">0x23</span>, <span class="pl-c1">0x8f</span>, <span class="pl-c1">0x5d</span>, <span class="pl-c1">0xff</span>, <span class="pl-c1">0x95</span>, <span class="pl-c1">0xe7</span>, <span class="pl-c1">0x70</span>, <span class="pl-c1">0x73</span>, <span class="pl-c1">0x12</span>, <span class="pl-c1">0x50</span>, <span class="pl-c1">0xe6</span>, <span class="pl-c1">0xce</span>, <span class="pl-c1">0x05</span>, <span class="pl-c1">0x9c</span>,</td>
      </tr>
      <tr>
        <td id="L892" class="blob-num js-line-number" data-line-number="892"></td>
        <td id="LC892" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x1b</span>, <span class="pl-c1">0x27</span>, <span class="pl-c1">0x70</span>, <span class="pl-c1">0x69</span>, <span class="pl-c1">0x66</span>, <span class="pl-c1">0xb5</span>, <span class="pl-c1">0x76</span>, <span class="pl-c1">0xa1</span>, <span class="pl-c1">0xbc</span>, <span class="pl-c1">0xd6</span>, <span class="pl-c1">0x90</span>, <span class="pl-c1">0x93</span>, <span class="pl-c1">0x95</span>, <span class="pl-c1">0x48</span>, <span class="pl-c1">0x4a</span>, <span class="pl-c1">0x30</span>,</td>
      </tr>
      <tr>
        <td id="L893" class="blob-num js-line-number" data-line-number="893"></td>
        <td id="LC893" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x9a</span>, <span class="pl-c1">0x6c</span>, <span class="pl-c1">0x8a</span>, <span class="pl-c1">0xe8</span>, <span class="pl-c1">0x9d</span>, <span class="pl-c1">0x7f</span>, <span class="pl-c1">0xe7</span>, <span class="pl-c1">0xe1</span>, <span class="pl-c1">0x70</span>, <span class="pl-c1">0x4b</span>, <span class="pl-c1">0xf3</span>, <span class="pl-c1">0xfd</span>, <span class="pl-c1">0x4e</span>, <span class="pl-c1">0xc4</span>, <span class="pl-c1">0xc2</span>, <span class="pl-c1">0x35</span>,</td>
      </tr>
      <tr>
        <td id="L894" class="blob-num js-line-number" data-line-number="894"></td>
        <td id="LC894" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x12</span>, <span class="pl-c1">0xf1</span>, <span class="pl-c1">0x26</span>, <span class="pl-c1">0x14</span>, <span class="pl-c1">0x28</span>, <span class="pl-c1">0xf3</span>, <span class="pl-c1">0x18</span>, <span class="pl-c1">0x11</span>, <span class="pl-c1">0x79</span>, <span class="pl-c1">0x58</span>, <span class="pl-c1">0xc3</span>, <span class="pl-c1">0xc9</span>, <span class="pl-c1">0x06</span>, <span class="pl-c1">0x7d</span>, <span class="pl-c1">0x0b</span>, <span class="pl-c1">0x55</span>,</td>
      </tr>
      <tr>
        <td id="L895" class="blob-num js-line-number" data-line-number="895"></td>
        <td id="LC895" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x3f</span>, <span class="pl-c1">0x0a</span>, <span class="pl-c1">0x29</span>, <span class="pl-c1">0x8b</span>, <span class="pl-c1">0xbd</span>, <span class="pl-c1">0x20</span>, <span class="pl-c1">0x64</span>, <span class="pl-c1">0x54</span>, <span class="pl-c1">0xe6</span>, <span class="pl-c1">0x96</span>, <span class="pl-c1">0xf3</span>, <span class="pl-c1">0x0e</span>, <span class="pl-c1">0x28</span>, <span class="pl-c1">0x3f</span>, <span class="pl-c1">0x69</span>, <span class="pl-c1">0xad</span>,</td>
      </tr>
      <tr>
        <td id="L896" class="blob-num js-line-number" data-line-number="896"></td>
        <td id="LC896" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x60</span>, <span class="pl-c1">0x71</span>, <span class="pl-c1">0xf6</span>, <span class="pl-c1">0x8e</span>, <span class="pl-c1">0x3b</span>, <span class="pl-c1">0xff</span>, <span class="pl-c1">0x51</span>, <span class="pl-c1">0xa0</span>, <span class="pl-c1">0x9a</span>, <span class="pl-c1">0x79</span>, <span class="pl-c1">0x88</span>, <span class="pl-c1">0x7e</span>, <span class="pl-c1">0x0a</span>, <span class="pl-c1">0x68</span>, <span class="pl-c1">0xea</span>, <span class="pl-c1">0xbd</span>,</td>
      </tr>
      <tr>
        <td id="L897" class="blob-num js-line-number" data-line-number="897"></td>
        <td id="LC897" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x4a</span>, <span class="pl-c1">0xbd</span>, <span class="pl-c1">0x9f</span>, <span class="pl-c1">0x96</span>, <span class="pl-c1">0x55</span>, <span class="pl-c1">0x4e</span>, <span class="pl-c1">0x7c</span>, <span class="pl-c1">0x01</span>, <span class="pl-c1">0x6b</span>, <span class="pl-c1">0x53</span>, <span class="pl-c1">0xef</span>, <span class="pl-c1">0x55</span>, <span class="pl-c1">0x02</span>, <span class="pl-c1">0x2b</span>, <span class="pl-c1">0x0b</span>, <span class="pl-c1">0x27</span>,</td>
      </tr>
      <tr>
        <td id="L898" class="blob-num js-line-number" data-line-number="898"></td>
        <td id="LC898" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xfa</span>, <span class="pl-c1">0x19</span>, <span class="pl-c1">0xdc</span>, <span class="pl-c1">0xe4</span>, <span class="pl-c1">0xda</span>, <span class="pl-c1">0x3c</span>, <span class="pl-c1">0x8b</span>, <span class="pl-c1">0x9f</span>, <span class="pl-c1">0x7b</span>, <span class="pl-c1">0x74</span>, <span class="pl-c1">0xa5</span>, <span class="pl-c1">0x9f</span>, <span class="pl-c1">0x13</span>, <span class="pl-c1">0xfa</span>, <span class="pl-c1">0x1c</span>, <span class="pl-c1">0xa9</span>,</td>
      </tr>
      <tr>
        <td id="L899" class="blob-num js-line-number" data-line-number="899"></td>
        <td id="LC899" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x2d</span>, <span class="pl-c1">0x1f</span>, <span class="pl-c1">0xa5</span>, <span class="pl-c1">0x27</span>, <span class="pl-c1">0x6e</span>, <span class="pl-c1">0x41</span>, <span class="pl-c1">0x31</span>, <span class="pl-c1">0x26</span>, <span class="pl-c1">0x2f</span>, <span class="pl-c1">0x78</span>, <span class="pl-c1">0x8e</span>, <span class="pl-c1">0xf3</span>, <span class="pl-c1">0x37</span>, <span class="pl-c1">0xaf</span>, <span class="pl-c1">0x60</span>, <span class="pl-c1">0xb9</span>,</td>
      </tr>
      <tr>
        <td id="L900" class="blob-num js-line-number" data-line-number="900"></td>
        <td id="LC900" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x43</span>, <span class="pl-c1">0x7f</span>, <span class="pl-c1">0x80</span>, <span class="pl-c1">0x5b</span>, <span class="pl-c1">0x74</span>, <span class="pl-c1">0x3e</span>, <span class="pl-c1">0x9b</span>, <span class="pl-c1">0x45</span>, <span class="pl-c1">0x31</span>, <span class="pl-c1">0x23</span>, <span class="pl-c1">0x23</span>, <span class="pl-c1">0xd7</span>, <span class="pl-c1">0x8f</span>, <span class="pl-c1">0xa6</span>, <span class="pl-c1">0xb3</span>, <span class="pl-c1">0x98</span>,</td>
      </tr>
      <tr>
        <td id="L901" class="blob-num js-line-number" data-line-number="901"></td>
        <td id="LC901" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x50</span>, <span class="pl-c1">0x1a</span>, <span class="pl-c1">0x44</span>, <span class="pl-c1">0xe1</span>, <span class="pl-c1">0x6b</span>, <span class="pl-c1">0x3b</span>, <span class="pl-c1">0x44</span>, <span class="pl-c1">0x6b</span>, <span class="pl-c1">0xa5</span>, <span class="pl-c1">0x27</span>, <span class="pl-c1">0x68</span>, <span class="pl-c1">0x3e</span>, <span class="pl-c1">0x5a</span>, <span class="pl-c1">0x42</span>, <span class="pl-c1">0x64</span>, <span class="pl-c1">0x9e</span>,</td>
      </tr>
      <tr>
        <td id="L902" class="blob-num js-line-number" data-line-number="902"></td>
        <td id="LC902" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x50</span>, <span class="pl-c1">0xfd</span>, <span class="pl-c1">0x4f</span>, <span class="pl-c1">0x25</span>, <span class="pl-c1">0xf8</span>, <span class="pl-c1">0xf8</span>, <span class="pl-c1">0x2a</span>, <span class="pl-c1">0xc2</span>, <span class="pl-c1">0x64</span>, <span class="pl-c1">0x2a</span>, <span class="pl-c1">0x5e</span>, <span class="pl-c1">0xc2</span>, <span class="pl-c1">0xd1</span>, <span class="pl-c1">0x7a</span>, <span class="pl-c1">0xd4</span>, <span class="pl-c1">0x27</span>,</td>
      </tr>
      <tr>
        <td id="L903" class="blob-num js-line-number" data-line-number="903"></td>
        <td id="LC903" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xf2</span>, <span class="pl-c1">0x34</span>, <span class="pl-c1">0x31</span>, <span class="pl-c1">0xcd</span>, <span class="pl-c1">0xb7</span>, <span class="pl-c1">0xf1</span>, <span class="pl-c1">0x41</span>, <span class="pl-c1">0x72</span>, <span class="pl-c1">0x74</span>, <span class="pl-c1">0xcd</span>, <span class="pl-c1">0x09</span>, <span class="pl-c1">0x89</span>, <span class="pl-c1">0x08</span>, <span class="pl-c1">0xdf</span>, <span class="pl-c1">0x98</span>, <span class="pl-c1">0x6c</span>,</td>
      </tr>
      <tr>
        <td id="L904" class="blob-num js-line-number" data-line-number="904"></td>
        <td id="LC904" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xc9</span>, <span class="pl-c1">0x28</span>, <span class="pl-c1">0xea</span>, <span class="pl-c1">0xc1</span>, <span class="pl-c1">0xd1</span>, <span class="pl-c1">0x34</span>, <span class="pl-c1">0x08</span>, <span class="pl-c1">0x83</span>, <span class="pl-c1">0xe9</span>, <span class="pl-c1">0x7c</span>, <span class="pl-c1">0xea</span>, <span class="pl-c1">0x2e</span>, <span class="pl-c1">0xbc</span>, <span class="pl-c1">0x80</span>, <span class="pl-c1">0xad</span>, <span class="pl-c1">0x8a</span>,</td>
      </tr>
      <tr>
        <td id="L905" class="blob-num js-line-number" data-line-number="905"></td>
        <td id="LC905" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x60</span>, <span class="pl-c1">0x6e</span>, <span class="pl-c1">0x8f</span>, <span class="pl-c1">0x22</span>, <span class="pl-c1">0x78</span>, <span class="pl-c1">0x43</span>, <span class="pl-c1">0x1e</span>, <span class="pl-c1">0x3d</span>, <span class="pl-c1">0xf7</span>, <span class="pl-c1">0x02</span>, <span class="pl-c1">0x96</span>, <span class="pl-c1">0x0a</span>, <span class="pl-c1">0xef</span>, <span class="pl-c1">0xfc</span>, <span class="pl-c1">0xad</span>, <span class="pl-c1">0x00</span>,</td>
      </tr>
      <tr>
        <td id="L906" class="blob-num js-line-number" data-line-number="906"></td>
        <td id="LC906" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x68</span>, <span class="pl-c1">0xfb</span>, <span class="pl-c1">0xf6</span>, <span class="pl-c1">0xeb</span>, <span class="pl-c1">0x27</span>, <span class="pl-c1">0xd3</span>, <span class="pl-c1">0xce</span>, <span class="pl-c1">0x2c</span>, <span class="pl-c1">0xc8</span>, <span class="pl-c1">0x5d</span>, <span class="pl-c1">0x23</span>, <span class="pl-c1">0x0b</span>, <span class="pl-c1">0xb6</span>, <span class="pl-c1">0xb2</span>, <span class="pl-c1">0x53</span>, <span class="pl-c1">0xfd</span>,</td>
      </tr>
      <tr>
        <td id="L907" class="blob-num js-line-number" data-line-number="907"></td>
        <td id="LC907" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x41</span>, <span class="pl-c1">0xd9</span>, <span class="pl-c1">0xb9</span>, <span class="pl-c1">0x80</span>, <span class="pl-c1">0x7a</span>, <span class="pl-c1">0xea</span>, <span class="pl-c1">0xb0</span>, <span class="pl-c1">0x04</span>, <span class="pl-c1">0x26</span>, <span class="pl-c1">0x2f</span>, <span class="pl-c1">0x60</span>, <span class="pl-c1">0xf0</span>, <span class="pl-c1">0x3b</span>, <span class="pl-c1">0x71</span>, <span class="pl-c1">0xda</span>, <span class="pl-c1">0x49</span>,</td>
      </tr>
      <tr>
        <td id="L908" class="blob-num js-line-number" data-line-number="908"></td>
        <td id="LC908" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xba</span>, <span class="pl-c1">0x48</span>, <span class="pl-c1">0x2e</span>, <span class="pl-c1">0x8e</span>, <span class="pl-c1">0x33</span>, <span class="pl-c1">0x3b</span>, <span class="pl-c1">0xf4</span>, <span class="pl-c1">0x5b</span>, <span class="pl-c1">0xa8</span>, <span class="pl-c1">0x78</span>, <span class="pl-c1">0xa3</span>, <span class="pl-c1">0x51</span>, <span class="pl-c1">0xc0</span>, <span class="pl-c1">0x44</span>, <span class="pl-c1">0x9c</span>, <span class="pl-c1">0x16</span>,</td>
      </tr>
      <tr>
        <td id="L909" class="blob-num js-line-number" data-line-number="909"></td>
        <td id="LC909" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x44</span>, <span class="pl-c1">0xa4</span>, <span class="pl-c1">0xe8</span>, <span class="pl-c1">0x6f</span>, <span class="pl-c1">0x20</span>, <span class="pl-c1">0xa2</span>, <span class="pl-c1">0x4f</span>, <span class="pl-c1">0x18</span>, <span class="pl-c1">0x5e</span>, <span class="pl-c1">0x1d</span>, <span class="pl-c1">0x42</span>, <span class="pl-c1">0xbf</span>, <span class="pl-c1">0x86</span>, <span class="pl-c1">0x72</span>, <span class="pl-c1">0x4c</span>, <span class="pl-c1">0xa6</span>,</td>
      </tr>
      <tr>
        <td id="L910" class="blob-num js-line-number" data-line-number="910"></td>
        <td id="LC910" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xd1</span>, <span class="pl-c1">0x4b</span>, <span class="pl-c1">0x6f</span>, <span class="pl-c1">0x42</span>, <span class="pl-c1">0x9b</span>, <span class="pl-c1">0xc5</span>, <span class="pl-c1">0xbd</span>, <span class="pl-c1">0x01</span>, <span class="pl-c1">0x96</span>, <span class="pl-c1">0x67</span>, <span class="pl-c1">0xd0</span>, <span class="pl-c1">0x03</span>, <span class="pl-c1">0xd0</span>, <span class="pl-c1">0x42</span>, <span class="pl-c1">0xb2</span>, <span class="pl-c1">0x70</span>,</td>
      </tr>
      <tr>
        <td id="L911" class="blob-num js-line-number" data-line-number="911"></td>
        <td id="LC911" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x93</span>, <span class="pl-c1">0xda</span>, <span class="pl-c1">0xed</span>, <span class="pl-c1">0x26</span>, <span class="pl-c1">0x25</span>, <span class="pl-c1">0xa5</span>, <span class="pl-c1">0x24</span>, <span class="pl-c1">0x4a</span>, <span class="pl-c1">0x4a</span>, <span class="pl-c1">0x23</span>, <span class="pl-c1">0x24</span>, <span class="pl-c1">0x8b</span>, <span class="pl-c1">0xa4</span>, <span class="pl-c1">0xbc</span>, <span class="pl-c1">0xf7</span>, <span class="pl-c1">0x45</span>,</td>
      </tr>
      <tr>
        <td id="L912" class="blob-num js-line-number" data-line-number="912"></td>
        <td id="LC912" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x6d</span>, <span class="pl-c1">0xf9</span>, <span class="pl-c1">0x39</span>, <span class="pl-c1">0x94</span>, <span class="pl-c1">0xfd</span>, <span class="pl-c1">0x31</span>, <span class="pl-c1">0xf1</span>, <span class="pl-c1">0xbf</span>, <span class="pl-c1">0xa1</span>, <span class="pl-c1">0xf3</span>, <span class="pl-c1">0x69</span>, <span class="pl-c1">0xb3</span>, <span class="pl-c1">0x7c</span>, <span class="pl-c1">0x75</span>, <span class="pl-c1">0x64</span>, <span class="pl-c1">0xb5</span>,</td>
      </tr>
      <tr>
        <td id="L913" class="blob-num js-line-number" data-line-number="913"></td>
        <td id="LC913" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xa4</span>, <span class="pl-c1">0x0e</span>, <span class="pl-c1">0x5e</span>, <span class="pl-c1">0x6a</span>, <span class="pl-c1">0xeb</span>, <span class="pl-c1">0x18</span>, <span class="pl-c1">0x6a</span>, <span class="pl-c1">0x59</span>, <span class="pl-c1">0x0e</span>, <span class="pl-c1">0xd0</span>, <span class="pl-c1">0x5d</span>, <span class="pl-c1">0xf8</span>, <span class="pl-c1">0x00</span>, <span class="pl-c1">0x9b</span>, <span class="pl-c1">0xfd</span>, <span class="pl-c1">0x9e</span>,</td>
      </tr>
      <tr>
        <td id="L914" class="blob-num js-line-number" data-line-number="914"></td>
        <td id="LC914" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x63</span>, <span class="pl-c1">0xf7</span>, <span class="pl-c1">0x4d</span>, <span class="pl-c1">0x77</span>, <span class="pl-c1">0xf0</span>, <span class="pl-c1">0xac</span>, <span class="pl-c1">0x67</span>, <span class="pl-c1">0xba</span>, <span class="pl-c1">0x43</span>, <span class="pl-c1">0xbb</span>, <span class="pl-c1">0xdf</span>, <span class="pl-c1">0x33</span>, <span class="pl-c1">0x5b</span>, <span class="pl-c1">0x56</span>, <span class="pl-c1">0xc7</span>, <span class="pl-c1">0x32</span>,</td>
      </tr>
      <tr>
        <td id="L915" class="blob-num js-line-number" data-line-number="915"></td>
        <td id="LC915" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xdb</span>, <span class="pl-c1">0xda</span>, <span class="pl-c1">0x8f</span>, <span class="pl-c1">0x10</span>, <span class="pl-c1">0x82</span>, <span class="pl-c1">0x46</span>, <span class="pl-c1">0xcf</span>, <span class="pl-c1">0xc0</span>, <span class="pl-c1">0x03</span>, <span class="pl-c1">0xcb</span>, <span class="pl-c1">0xe8</span>, <span class="pl-c1">0xba</span>, <span class="pl-c1">0xc3</span>, <span class="pl-c1">0x5e</span>, <span class="pl-c1">0xdb</span>, <span class="pl-c1">0x18</span>,</td>
      </tr>
      <tr>
        <td id="L916" class="blob-num js-line-number" data-line-number="916"></td>
        <td id="LC916" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x98</span>, <span class="pl-c1">0x9a</span>, <span class="pl-c1">0x82</span>, <span class="pl-c1">0x0e</span>, <span class="pl-c1">0xa0</span>, <span class="pl-c1">0xda</span>, <span class="pl-c1">0x19</span>, <span class="pl-c1">0x76</span>, <span class="pl-c1">0x97</span>, <span class="pl-c1">0x82</span>, <span class="pl-c1">0x9c</span>, <span class="pl-c1">0xfe</span>, <span class="pl-c1">0x4f</span>, <span class="pl-c1">0x05</span>, <span class="pl-c1">0x8e</span>, <span class="pl-c1">0x78</span>,</td>
      </tr>
      <tr>
        <td id="L917" class="blob-num js-line-number" data-line-number="917"></td>
        <td id="LC917" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x63</span>, <span class="pl-c1">0xec</span>, <span class="pl-c1">0xcc</span>, <span class="pl-c1">0x27</span>, <span class="pl-c1">0x93</span>, <span class="pl-c1">0x53</span>, <span class="pl-c1">0x8f</span>, <span class="pl-c1">0xbe</span>, <span class="pl-c1">0x83</span>, <span class="pl-c1">0x56</span>, <span class="pl-c1">0x7d</span>, <span class="pl-c1">0x1f</span>, <span class="pl-c1">0xea</span>, <span class="pl-c1">0x59</span>, <span class="pl-c1">0x16</span>, <span class="pl-c1">0x92</span>,</td>
      </tr>
      <tr>
        <td id="L918" class="blob-num js-line-number" data-line-number="918"></td>
        <td id="LC918" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x31</span>, <span class="pl-c1">0xb5</span>, <span class="pl-c1">0x86</span>, <span class="pl-c1">0x6b</span>, <span class="pl-c1">0xfe</span>, <span class="pl-c1">0x8a</span>, <span class="pl-c1">0x03</span>, <span class="pl-c1">0xba</span>, <span class="pl-c1">0xd9</span>, <span class="pl-c1">0xcf</span>, <span class="pl-c1">0xd5</span>, <span class="pl-c1">0xb7</span>, <span class="pl-c1">0xee</span>, <span class="pl-c1">0xe7</span>, <span class="pl-c1">0xff</span>, <span class="pl-c1">0x57</span>,</td>
      </tr>
      <tr>
        <td id="L919" class="blob-num js-line-number" data-line-number="919"></td>
        <td id="LC919" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xe0</span>, <span class="pl-c1">0xd6</span>, <span class="pl-c1">0xa6</span>, <span class="pl-c1">0xdd</span>, <span class="pl-c1">0xd7</span>, <span class="pl-c1">0xee</span>, <span class="pl-c1">0xe6</span>, <span class="pl-c1">0xef</span>, <span class="pl-c1">0xbe</span>, <span class="pl-c1">0x04</span>, <span class="pl-c1">0xa0</span>, <span class="pl-c1">0x01</span>, <span class="pl-c1">0xdc</span>, <span class="pl-c1">0x0e</span>, <span class="pl-c1">0xc9</span>, <span class="pl-c1">0x0b</span>,</td>
      </tr>
      <tr>
        <td id="L920" class="blob-num js-line-number" data-line-number="920"></td>
        <td id="LC920" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x8f</span>, <span class="pl-c1">0x05</span>, <span class="pl-c1">0x2f</span>, <span class="pl-c1">0x89</span>, <span class="pl-c1">0xbb</span>, <span class="pl-c1">0x31</span>, <span class="pl-c1">0x5b</span>, <span class="pl-c1">0xa9</span>, <span class="pl-c1">0x7b</span>, <span class="pl-c1">0x60</span>, <span class="pl-c1">0x1e</span>, <span class="pl-c1">0xa5</span>, <span class="pl-c1">0x87</span>, <span class="pl-c1">0x5b</span>, <span class="pl-c1">0x6b</span>, <span class="pl-c1">0x33</span>,</td>
      </tr>
      <tr>
        <td id="L921" class="blob-num js-line-number" data-line-number="921"></td>
        <td id="LC921" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x56</span>, <span class="pl-c1">0x0f</span>, <span class="pl-c1">0x60</span>, <span class="pl-c1">0xc5</span>, <span class="pl-c1">0x3c</span>, <span class="pl-c1">0xfa</span>, <span class="pl-c1">0x10</span>, <span class="pl-c1">0x2a</span>, <span class="pl-c1">0x92</span>, <span class="pl-c1">0xf1</span>, <span class="pl-c1">0x60</span>, <span class="pl-c1">0x24</span>, <span class="pl-c1">0x9c</span>, <span class="pl-c1">0x55</span>, <span class="pl-c1">0xc1</span>, <span class="pl-c1">0xe5</span>,</td>
      </tr>
      <tr>
        <td id="L922" class="blob-num js-line-number" data-line-number="922"></td>
        <td id="LC922" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x44</span>, <span class="pl-c1">0x60</span>, <span class="pl-c1">0x8d</span>, <span class="pl-c1">0xd0</span>, <span class="pl-c1">0xa7</span>, <span class="pl-c1">0xd0</span>, <span class="pl-c1">0x90</span>, <span class="pl-c1">0x0f</span>, <span class="pl-c1">0x5f</span>, <span class="pl-c1">0x92</span>, <span class="pl-c1">0x98</span>, <span class="pl-c1">0xa6</span>, <span class="pl-c1">0xef</span>, <span class="pl-c1">0x52</span>, <span class="pl-c1">0xc1</span>, <span class="pl-c1">0xd2</span>,</td>
      </tr>
      <tr>
        <td id="L923" class="blob-num js-line-number" data-line-number="923"></td>
        <td id="LC923" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x49</span>, <span class="pl-c1">0x4f</span>, <span class="pl-c1">0x12</span>, <span class="pl-c1">0xa1</span>, <span class="pl-c1">0xae</span>, <span class="pl-c1">0x43</span>, <span class="pl-c1">0x39</span>, <span class="pl-c1">0x8d</span>, <span class="pl-c1">0x38</span>, <span class="pl-c1">0xde</span>, <span class="pl-c1">0x1a</span>, <span class="pl-c1">0xe8</span>, <span class="pl-c1">0xd8</span>, <span class="pl-c1">0x7b</span>, <span class="pl-c1">0xf4</span>, <span class="pl-c1">0xf9</span>,</td>
      </tr>
      <tr>
        <td id="L924" class="blob-num js-line-number" data-line-number="924"></td>
        <td id="LC924" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x17</span>, <span class="pl-c1">0x02</span>, <span class="pl-c1">0xac</span>, <span class="pl-c1">0x86</span>, <span class="pl-c1">0xe5</span>, <span class="pl-c1">0x4e</span>, <span class="pl-c1">0xff</span>, <span class="pl-c1">0x2c</span>, <span class="pl-c1">0x1d</span>, <span class="pl-c1">0xce</span>, <span class="pl-c1">0x45</span>, <span class="pl-c1">0xfc</span>, <span class="pl-c1">0x23</span>, <span class="pl-c1">0x04</span>, <span class="pl-c1">0xf9</span>, <span class="pl-c1">0xb1</span>,</td>
      </tr>
      <tr>
        <td id="L925" class="blob-num js-line-number" data-line-number="925"></td>
        <td id="LC925" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x47</span>, <span class="pl-c1">0xc7</span>, <span class="pl-c1">0x52</span>, <span class="pl-c1">0x49</span>, <span class="pl-c1">0xac</span>, <span class="pl-c1">0x91</span>, <span class="pl-c1">0x06</span>, <span class="pl-c1">0xea</span>, <span class="pl-c1">0x3c</span>, <span class="pl-c1">0x9e</span>, <span class="pl-c1">0xc8</span>, <span class="pl-c1">0x2b</span>, <span class="pl-c1">0xf8</span>, <span class="pl-c1">0x52</span>, <span class="pl-c1">0xff</span>, <span class="pl-c1">0x5f</span>,</td>
      </tr>
      <tr>
        <td id="L926" class="blob-num js-line-number" data-line-number="926"></td>
        <td id="LC926" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x0e</span>, <span class="pl-c1">0x1a</span>, <span class="pl-c1">0xeb</span>, <span class="pl-c1">0x59</span>, <span class="pl-c1">0x83</span>, <span class="pl-c1">0x6c</span>, <span class="pl-c1">0xd0</span>, <span class="pl-c1">0x32</span>, <span class="pl-c1">0x8d</span>, <span class="pl-c1">0x25</span>, <span class="pl-c1">0x5b</span>, <span class="pl-c1">0x04</span>, <span class="pl-c1">0xf7</span>, <span class="pl-c1">0x6a</span>, <span class="pl-c1">0x2e</span>, <span class="pl-c1">0x07</span>,</td>
      </tr>
      <tr>
        <td id="L927" class="blob-num js-line-number" data-line-number="927"></td>
        <td id="LC927" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xfe</span>, <span class="pl-c1">0xba</span>, <span class="pl-c1">0x00</span>, <span class="pl-c1">0xfd</span>, <span class="pl-c1">0x0a</span>, <span class="pl-c1">0x20</span>, <span class="pl-c1">0xf6</span>, <span class="pl-c1">0x16</span>, <span class="pl-c1">0xee</span>, <span class="pl-c1">0x58</span>, <span class="pl-c1">0x84</span>, <span class="pl-c1">0x81</span>, <span class="pl-c1">0x74</span>, <span class="pl-c1">0xd5</span>, <span class="pl-c1">0xdd</span>, <span class="pl-c1">0x5d</span>,</td>
      </tr>
      <tr>
        <td id="L928" class="blob-num js-line-number" data-line-number="928"></td>
        <td id="LC928" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x48</span>, <span class="pl-c1">0xd8</span>, <span class="pl-c1">0x5b</span>, <span class="pl-c1">0xc8</span>, <span class="pl-c1">0x58</span>, <span class="pl-c1">0xa9</span>, <span class="pl-c1">0xc4</span>, <span class="pl-c1">0xe9</span>, <span class="pl-c1">0x92</span>, <span class="pl-c1">0x87</span>, <span class="pl-c1">0x22</span>, <span class="pl-c1">0x3f</span>, <span class="pl-c1">0x1d</span>, <span class="pl-c1">0x84</span>, <span class="pl-c1">0xa3</span>, <span class="pl-c1">0xc0</span>,</td>
      </tr>
      <tr>
        <td id="L929" class="blob-num js-line-number" data-line-number="929"></td>
        <td id="LC929" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x17</span>, <span class="pl-c1">0x1f</span>, <span class="pl-c1">0x2e</span>, <span class="pl-c1">0x57</span>, <span class="pl-c1">0x86</span>, <span class="pl-c1">0x22</span>, <span class="pl-c1">0xf6</span>, <span class="pl-c1">0x16</span>, <span class="pl-c1">0x56</span>, <span class="pl-c1">0xa2</span>, <span class="pl-c1">0x85</span>, <span class="pl-c1">0xf9</span>, <span class="pl-c1">0x85</span>, <span class="pl-c1">0x72</span>, <span class="pl-c1">0x8d</span>, <span class="pl-c1">0x3a</span>,</td>
      </tr>
      <tr>
        <td id="L930" class="blob-num js-line-number" data-line-number="930"></td>
        <td id="LC930" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x50</span>, <span class="pl-c1">0x8d</span>, <span class="pl-c1">0x03</span>, <span class="pl-c1">0x9f</span>, <span class="pl-c1">0xa4</span>, <span class="pl-c1">0xf7</span>, <span class="pl-c1">0x27</span>, <span class="pl-c1">0xc3</span>, <span class="pl-c1">0xc2</span>, <span class="pl-c1">0xa7</span>, <span class="pl-c1">0x3b</span>, <span class="pl-c1">0x01</span>, <span class="pl-c1">0x02</span>, <span class="pl-c1">0x9f</span>, <span class="pl-c1">0xb4</span>, <span class="pl-c1">0xc9</span>,</td>
      </tr>
      <tr>
        <td id="L931" class="blob-num js-line-number" data-line-number="931"></td>
        <td id="LC931" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x84</span>, <span class="pl-c1">0x79</span>, <span class="pl-c1">0x66</span>, <span class="pl-c1">0xe8</span>, <span class="pl-c1">0x47</span>, <span class="pl-c1">0xa3</span>, <span class="pl-c1">0x20</span>, <span class="pl-c1">0x7c</span>, <span class="pl-c1">0x81</span>, <span class="pl-c1">0x81</span>, <span class="pl-c1">0x9f</span>, <span class="pl-c1">0x94</span>, <span class="pl-c1">0x86</span>, <span class="pl-c1">0x9c</span>, <span class="pl-c1">0x42</span>, <span class="pl-c1">0x4d</span>,</td>
      </tr>
      <tr>
        <td id="L932" class="blob-num js-line-number" data-line-number="932"></td>
        <td id="LC932" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xe0</span>, <span class="pl-c1">0xa4</span>, <span class="pl-c1">0x96</span>, <span class="pl-c1">0x14</span>, <span class="pl-c1">0xde</span>, <span class="pl-c1">0x06</span>, <span class="pl-c1">0x48</span>, <span class="pl-c1">0x98</span>, <span class="pl-c1">0x20</span>, <span class="pl-c1">0x2d</span>, <span class="pl-c1">0xd2</span>, <span class="pl-c1">0x7f</span>, <span class="pl-c1">0x0c</span>, <span class="pl-c1">0xb0</span>, <span class="pl-c1">0xb2</span>, <span class="pl-c1">0x15</span>,</td>
      </tr>
      <tr>
        <td id="L933" class="blob-num js-line-number" data-line-number="933"></td>
        <td id="LC933" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x35</span>, <span class="pl-c1">0xa1</span>, <span class="pl-c1">0x94</span>, <span class="pl-c1">0x42</span>, <span class="pl-c1">0xf2</span>, <span class="pl-c1">0x7c</span>, <span class="pl-c1">0x28</span>, <span class="pl-c1">0xe0</span>, <span class="pl-c1">0x74</span>, <span class="pl-c1">0xab</span>, <span class="pl-c1">0x7f</span>, <span class="pl-c1">0x05</span>, <span class="pl-c1">0x95</span>, <span class="pl-c1">0x25</span>, <span class="pl-c1">0x25</span>, <span class="pl-c1">0xe8</span>,</td>
      </tr>
      <tr>
        <td id="L934" class="blob-num js-line-number" data-line-number="934"></td>
        <td id="LC934" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x1e</span>, <span class="pl-c1">0x54</span>, <span class="pl-c1">0x67</span>, <span class="pl-c1">0x31</span>, <span class="pl-c1">0xb9</span>, <span class="pl-c1">0x08</span>, <span class="pl-c1">0x5e</span>, <span class="pl-c1">0xb9</span>, <span class="pl-c1">0x34</span>, <span class="pl-c1">0xf8</span>, <span class="pl-c1">0x8e</span>, <span class="pl-c1">0xc8</span>, <span class="pl-c1">0x49</span>, <span class="pl-c1">0x03</span>, <span class="pl-c1">0x12</span>, <span class="pl-c1">0x51</span>,</td>
      </tr>
      <tr>
        <td id="L935" class="blob-num js-line-number" data-line-number="935"></td>
        <td id="LC935" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x3f</span>, <span class="pl-c1">0xf8</span>, <span class="pl-c1">0x8e</span>, <span class="pl-c1">0x97</span>, <span class="pl-c1">0x9b</span>, <span class="pl-c1">0x4d</span>, <span class="pl-c1">0x9a</span>, <span class="pl-c1">0x6b</span>, <span class="pl-c1">0x19</span>, <span class="pl-c1">0x1e</span>, <span class="pl-c1">0xf5</span>, <span class="pl-c1">0xbf</span>, <span class="pl-c1">0x2a</span>, <span class="pl-c1">0x70</span>, <span class="pl-c1">0xb8</span>, <span class="pl-c1">0x65</span>,</td>
      </tr>
      <tr>
        <td id="L936" class="blob-num js-line-number" data-line-number="936"></td>
        <td id="LC936" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x17</span>, <span class="pl-c1">0x47</span>, <span class="pl-c1">0xbd</span>, <span class="pl-c1">0x08</span>, <span class="pl-c1">0x62</span>, <span class="pl-c1">0xca</span>, <span class="pl-c1">0xdc</span>, <span class="pl-c1">0x97</span>, <span class="pl-c1">0xde</span>, <span class="pl-c1">0x64</span>, <span class="pl-c1">0x9e</span>, <span class="pl-c1">0xa0</span>, <span class="pl-c1">0xaa</span>, <span class="pl-c1">0x18</span>, <span class="pl-c1">0x84</span>, <span class="pl-c1">0xe8</span>,</td>
      </tr>
      <tr>
        <td id="L937" class="blob-num js-line-number" data-line-number="937"></td>
        <td id="LC937" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x09</span>, <span class="pl-c1">0x97</span>, <span class="pl-c1">0xf0</span>, <span class="pl-c1">0xf8</span>, <span class="pl-c1">0x14</span>, <span class="pl-c1">0x6f</span>, <span class="pl-c1">0x3d</span>, <span class="pl-c1">0xf3</span>, <span class="pl-c1">0x62</span>, <span class="pl-c1">0x6f</span>, <span class="pl-c1">0x4a</span>, <span class="pl-c1">0x18</span>, <span class="pl-c1">0x89</span>, <span class="pl-c1">0xe5</span>, <span class="pl-c1">0xcc</span>, <span class="pl-c1">0x52</span>,</td>
      </tr>
      <tr>
        <td id="L938" class="blob-num js-line-number" data-line-number="938"></td>
        <td id="LC938" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xe7</span>, <span class="pl-c1">0xd2</span>, <span class="pl-c1">0x5e</span>, <span class="pl-c1">0x2a</span>, <span class="pl-c1">0xe4</span>, <span class="pl-c1">0x38</span>, <span class="pl-c1">0xe1</span>, <span class="pl-c1">0x7c</span>, <span class="pl-c1">0x9a</span>, <span class="pl-c1">0xf9</span>, <span class="pl-c1">0xbc</span>, <span class="pl-c1">0x14</span>, <span class="pl-c1">0xd6</span>, <span class="pl-c1">0x85</span>, <span class="pl-c1">0xf3</span>, <span class="pl-c1">0x69</span>,</td>
      </tr>
      <tr>
        <td id="L939" class="blob-num js-line-number" data-line-number="939"></td>
        <td id="LC939" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x3a</span>, <span class="pl-c1">0xcf</span>, <span class="pl-c1">0x7c</span>, <span class="pl-c1">0x02</span>, <span class="pl-c1">0x35</span>, <span class="pl-c1">0xc2</span>, <span class="pl-c1">0x2f</span>, <span class="pl-c1">0x25</span>, <span class="pl-c1">0x23</span>, <span class="pl-c1">0x77</span>, <span class="pl-c1">0xf9</span>, <span class="pl-c1">0x3d</span>, <span class="pl-c1">0x54</span>, <span class="pl-c1">0xc3</span>, <span class="pl-c1">0x55</span>, <span class="pl-c1">0x29</span>,</td>
      </tr>
      <tr>
        <td id="L940" class="blob-num js-line-number" data-line-number="940"></td>
        <td id="LC940" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xe3</span>, <span class="pl-c1">0xd3</span>, <span class="pl-c1">0x0f</span>, <span class="pl-c1">0xb7</span>, <span class="pl-c1">0xf0</span>, <span class="pl-c1">0xc6</span>, <span class="pl-c1">0x8e</span>, <span class="pl-c1">0x6f</span>, <span class="pl-c1">0x21</span>, <span class="pl-c1">0xe4</span>, <span class="pl-c1">0x40</span>, <span class="pl-c1">0x69</span>, <span class="pl-c1">0x35</span>, <span class="pl-c1">0x5f</span>, <span class="pl-c1">0xf1</span>, <span class="pl-c1">0x82</span>,</td>
      </tr>
      <tr>
        <td id="L941" class="blob-num js-line-number" data-line-number="941"></td>
        <td id="LC941" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xf1</span>, <span class="pl-c1">0xf9</span>, <span class="pl-c1">0x9e</span>, <span class="pl-c1">0x5f</span>, <span class="pl-c1">0x51</span>, <span class="pl-c1">0x27</span>, <span class="pl-c1">0xe9</span>, <span class="pl-c1">0x22</span>, <span class="pl-c1">0xf9</span>, <span class="pl-c1">0x46</span>, <span class="pl-c1">0x4b</span>, <span class="pl-c1">0x51</span>, <span class="pl-c1">0xee</span>, <span class="pl-c1">0x7c</span>, <span class="pl-c1">0x09</span>, <span class="pl-c1">0xf5</span>,</td>
      </tr>
      <tr>
        <td id="L942" class="blob-num js-line-number" data-line-number="942"></td>
        <td id="LC942" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xb5</span>, <span class="pl-c1">0x27</span>, <span class="pl-c1">0x3c</span>, <span class="pl-c1">0x2d</span>, <span class="pl-c1">0xbe</span>, <span class="pl-c1">0x21</span>, <span class="pl-c1">0x97</span>, <span class="pl-c1">0x32</span>, <span class="pl-c1">0x53</span>, <span class="pl-c1">0xf8</span>, <span class="pl-c1">0x92</span>, <span class="pl-c1">0xcf</span>, <span class="pl-c1">0x9d</span>, <span class="pl-c1">0x09</span>, <span class="pl-c1">0x23</span>, <span class="pl-c1">0x09</span>,</td>
      </tr>
      <tr>
        <td id="L943" class="blob-num js-line-number" data-line-number="943"></td>
        <td id="LC943" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x8f</span>, <span class="pl-c1">0xc9</span>, <span class="pl-c1">0x46</span>, <span class="pl-c1">0xff</span>, <span class="pl-c1">0xaf</span>, <span class="pl-c1">0x02</span>, <span class="pl-c1">0x37</span>, <span class="pl-c1">0x57</span>, <span class="pl-c1">0x3d</span>, <span class="pl-c1">0xb1</span>, <span class="pl-c1">0x4d</span>, <span class="pl-c1">0xa8</span>, <span class="pl-c1">0x1f</span>, <span class="pl-c1">0x07</span>, <span class="pl-c1">0x33</span>, <span class="pl-c1">0x16</span>,</td>
      </tr>
      <tr>
        <td id="L944" class="blob-num js-line-number" data-line-number="944"></td>
        <td id="LC944" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xc5</span>, <span class="pl-c1">0xef</span>, <span class="pl-c1">0xf7</span>, <span class="pl-c1">0xfc</span>, <span class="pl-c1">0xad</span>, <span class="pl-c1">0xfe</span>, <span class="pl-c1">0xf0</span>, <span class="pl-c1">0xc9</span>, <span class="pl-c1">0x43</span>, <span class="pl-c1">0xbf</span>, <span class="pl-c1">0x80</span>, <span class="pl-c1">0xdb</span>, <span class="pl-c1">0xfc</span>, <span class="pl-c1">0x55</span>, <span class="pl-c1">0x57</span>, <span class="pl-c1">0x2f</span>,</td>
      </tr>
      <tr>
        <td id="L945" class="blob-num js-line-number" data-line-number="945"></td>
        <td id="LC945" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xbd</span>, <span class="pl-c1">0xaa</span>, <span class="pl-c1">0xe3</span>, <span class="pl-c1">0x5f</span>, <span class="pl-c1">0x2d</span>, <span class="pl-c1">0xff</span>, <span class="pl-c1">0x99</span>, <span class="pl-c1">0xf0</span>, <span class="pl-c1">0x69</span>, <span class="pl-c1">0x2d</span>, <span class="pl-c1">0xf5</span>, <span class="pl-c1">0xcd</span>, <span class="pl-c1">0x83</span>, <span class="pl-c1">0xab</span>, <span class="pl-c1">0xaf</span>, <span class="pl-c1">0x59</span>,</td>
      </tr>
      <tr>
        <td id="L946" class="blob-num js-line-number" data-line-number="946"></td>
        <td id="LC946" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xe7</span>, <span class="pl-c1">0x2c</span>, <span class="pl-c1">0xfd</span>, <span class="pl-c1">0x7b</span>, <span class="pl-c1">0x22</span>, <span class="pl-c1">0x40</span>, <span class="pl-c1">0xf5</span>, <span class="pl-c1">0x5f</span>, <span class="pl-c1">0x42</span>, <span class="pl-c1">0x79</span>, <span class="pl-c1">0x59</span>, <span class="pl-c1">0x93</span>, <span class="pl-c1">0x9b</span>, <span class="pl-c1">0x50</span>, <span class="pl-c1">0xa2</span>, <span class="pl-c1">0xc4</span>,</td>
      </tr>
      <tr>
        <td id="L947" class="blob-num js-line-number" data-line-number="947"></td>
        <td id="LC947" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x8f</span>, <span class="pl-c1">0xc2</span>, <span class="pl-c1">0x11</span>, <span class="pl-c1">0x95</span>, <span class="pl-c1">0xf1</span>, <span class="pl-c1">0x98</span>, <span class="pl-c1">0x6e</span>, <span class="pl-c1">0xb9</span>, <span class="pl-c1">0x57</span>, <span class="pl-c1">0x42</span>, <span class="pl-c1">0x2f</span>, <span class="pl-c1">0x8c</span>, <span class="pl-c1">0xd2</span>, <span class="pl-c1">0xb9</span>, <span class="pl-c1">0x39</span>, <span class="pl-c1">0xd9</span>,</td>
      </tr>
      <tr>
        <td id="L948" class="blob-num js-line-number" data-line-number="948"></td>
        <td id="LC948" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x3c</span>, <span class="pl-c1">0xfc</span>, <span class="pl-c1">0xa3</span>, <span class="pl-c1">0x92</span>, <span class="pl-c1">0xfe</span>, <span class="pl-c1">0xcb</span>, <span class="pl-c1">0x11</span>, <span class="pl-c1">0x1c</span>, <span class="pl-c1">0x7c</span>, <span class="pl-c1">0x08</span>, <span class="pl-c1">0xb7</span>, <span class="pl-c1">0x07</span>, <span class="pl-c1">0xa7</span>, <span class="pl-c1">0xd8</span>, <span class="pl-c1">0x34</span>, <span class="pl-c1">0x06</span>,</td>
      </tr>
      <tr>
        <td id="L949" class="blob-num js-line-number" data-line-number="949"></td>
        <td id="LC949" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xbb</span>, <span class="pl-c1">0x9a</span>, <span class="pl-c1">0x6e</span>, <span class="pl-c1">0x15</span>, <span class="pl-c1">0x4a</span>, <span class="pl-c1">0x67</span>, <span class="pl-c1">0x46</span>, <span class="pl-c1">0xf7</span>, <span class="pl-c1">0xdc</span>, <span class="pl-c1">0xc0</span>, <span class="pl-c1">0xbc</span>, <span class="pl-c1">0xdb</span>, <span class="pl-c1">0xde</span>, <span class="pl-c1">0x02</span>, <span class="pl-c1">0xd4</span>, <span class="pl-c1">0x77</span>,</td>
      </tr>
      <tr>
        <td id="L950" class="blob-num js-line-number" data-line-number="950"></td>
        <td id="LC950" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x5a</span>, <span class="pl-c1">0xbc</span>, <span class="pl-c1">0x01</span>, <span class="pl-c1">0x9b</span>, <span class="pl-c1">0xf6</span>, <span class="pl-c1">0x63</span>, <span class="pl-c1">0xcb</span>, <span class="pl-c1">0x36</span>, <span class="pl-c1">0x4d</span>, <span class="pl-c1">0x6c</span>, <span class="pl-c1">0xd9</span>, <span class="pl-c1">0x8f</span>, <span class="pl-c1">0xb5</span>, <span class="pl-c1">0x1c</span>, <span class="pl-c1">0x3a</span>, <span class="pl-c1">0x82</span>,</td>
      </tr>
      <tr>
        <td id="L951" class="blob-num js-line-number" data-line-number="951"></td>
        <td id="LC951" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xc3</span>, <span class="pl-c1">0xa1</span>, <span class="pl-c1">0x7d</span>, <span class="pl-c1">0x6e</span>, <span class="pl-c1">0xd8</span>, <span class="pl-c1">0x03</span>, <span class="pl-c1">0xb3</span>, <span class="pl-c1">0xed</span>, <span class="pl-c1">0xf6</span>, <span class="pl-c1">0x9d</span>, <span class="pl-c1">0xce</span>, <span class="pl-c1">0x40</span>, <span class="pl-c1">0xa8</span>, <span class="pl-c1">0xab</span>, <span class="pl-c1">0xe8</span>, <span class="pl-c1">0x3e</span>,</td>
      </tr>
      <tr>
        <td id="L952" class="blob-num js-line-number" data-line-number="952"></td>
        <td id="LC952" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xdc</span>, <span class="pl-c1">0xeb</span>, <span class="pl-c1">0x39</span>, <span class="pl-c1">0x03</span>, <span class="pl-c1">0xd3</span>, <span class="pl-c1">0xe6</span>, <span class="pl-c1">0x2d</span>, <span class="pl-c1">0xbb</span>, <span class="pl-c1">0xfb</span>, <span class="pl-c1">0xcc</span>, <span class="pl-c1">0x3d</span>, <span class="pl-c1">0x35</span>, <span class="pl-c1">0xf0</span>, <span class="pl-c1">0x59</span>, <span class="pl-c1">0x67</span>, <span class="pl-c1">0xd8</span>,</td>
      </tr>
      <tr>
        <td id="L953" class="blob-num js-line-number" data-line-number="953"></td>
        <td id="LC953" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x75</span>, <span class="pl-c1">0x8d</span>, <span class="pl-c1">0x5e</span>, <span class="pl-c1">0xaf</span>, <span class="pl-c1">0x6b</span>, <span class="pl-c1">0xb5</span>, <span class="pl-c1">0x8c</span>, <span class="pl-c1">0x81</span>, <span class="pl-c1">0xe5</span>, <span class="pl-c1">0xd8</span>, <span class="pl-c1">0x5a</span>, <span class="pl-c1">0xfe</span>, <span class="pl-c1">0xe1</span>, <span class="pl-c1">0x5f</span>, <span class="pl-c1">0x14</span>, <span class="pl-c1">0xa8</span>,</td>
      </tr>
      <tr>
        <td id="L954" class="blob-num js-line-number" data-line-number="954"></td>
        <td id="LC954" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x65</span>, <span class="pl-c1">0x1d</span>, <span class="pl-c1">0xc4</span>, <span class="pl-c1">0xa7</span>, <span class="pl-c1">0x80</span>, <span class="pl-c1">0x5e</span>, <span class="pl-c1">0xd7</span>, <span class="pl-c1">0x18</span>, <span class="pl-c1">0x74</span>, <span class="pl-c1">0x1c</span>, <span class="pl-c1">0x7c</span>, <span class="pl-c1">0x76</span>, <span class="pl-c1">0x85</span>, <span class="pl-c1">0x41</span>, <span class="pl-c1">0xe7</span>, <span class="pl-c1">0x96</span>,</td>
      </tr>
      <tr>
        <td id="L955" class="blob-num js-line-number" data-line-number="955"></td>
        <td id="LC955" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xdd</span>, <span class="pl-c1">0x76</span>, <span class="pl-c1">0xce</span>, <span class="pl-c1">0xfb</span>, <span class="pl-c1">0x9a</span>, <span class="pl-c1">0x82</span>, <span class="pl-c1">0x2a</span>, <span class="pl-c1">0x50</span>, <span class="pl-c1">0xe8</span>, <span class="pl-c1">0x5a</span>, <span class="pl-c1">0xf6</span>, <span class="pl-c1">0xf0</span>, <span class="pl-c1">0xa9</span>, <span class="pl-c1">0x96</span>, <span class="pl-c1">0xe3</span>, <span class="pl-c1">0x72</span>,</td>
      </tr>
      <tr>
        <td id="L956" class="blob-num js-line-number" data-line-number="956"></td>
        <td id="LC956" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xc3</span>, <span class="pl-c1">0x6e</span>, <span class="pl-c1">0x63</span>, <span class="pl-c1">0xc7</span>, <span class="pl-c1">0x6a</span>, <span class="pl-c1">0x6b</span>, <span class="pl-c1">0x2a</span>, <span class="pl-c1">0x2a</span>, <span class="pl-c1">0x81</span>, <span class="pl-c1">0xea</span>, <span class="pl-c1">0xf4</span>, <span class="pl-c1">0x9f</span>, <span class="pl-c1">0x6a</span>, <span class="pl-c1">0x79</span>, <span class="pl-c1">0xbe</span>, <span class="pl-c1">0xb0</span>,</td>
      </tr>
      <tr>
        <td id="L957" class="blob-num js-line-number" data-line-number="957"></td>
        <td id="LC957" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x9c</span>, <span class="pl-c1">0xbe</span>, <span class="pl-c1">0x56</span>, <span class="pl-c1">0x40</span>, <span class="pl-c1">0x1a</span>, <span class="pl-c1">0xd4</span>, <span class="pl-c1">0x0c</span>, <span class="pl-c1">0xfb</span>, <span class="pl-c1">0x99</span>, <span class="pl-c1">0x9b</span>, <span class="pl-c1">0x22</span>, <span class="pl-c1">0x6b</span>, <span class="pl-c1">0x45</span>, <span class="pl-c1">0x74</span>, <span class="pl-c1">0x08</span>, <span class="pl-c1">0x75</span>,</td>
      </tr>
      <tr>
        <td id="L958" class="blob-num js-line-number" data-line-number="958"></td>
        <td id="LC958" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xa3</span>, <span class="pl-c1">0xdb</span>, <span class="pl-c1">0x5d</span>, <span class="pl-c1">0x4a</span>, <span class="pl-c1">0xfa</span>, <span class="pl-c1">0x5a</span>, <span class="pl-c1">0x09</span>, <span class="pl-c1">0x01</span>, <span class="pl-c1">0x14</span>, <span class="pl-c1">0x5b</span>, <span class="pl-c1">0xa7</span>, <span class="pl-c1">0xd8</span>, <span class="pl-c1">0x39</span>, <span class="pl-c1">0x33</span>, <span class="pl-c1">0xb5</span>, <span class="pl-c1">0xf2</span>,</td>
      </tr>
      <tr>
        <td id="L959" class="blob-num js-line-number" data-line-number="959"></td>
        <td id="LC959" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xc3</span>, <span class="pl-c1">0x0e</span>, <span class="pl-c1">0x1c</span>, <span class="pl-c1">0x6c</span>, <span class="pl-c1">0x14</span>, <span class="pl-c1">0x6a</span>, <span class="pl-c1">0x74</span>, <span class="pl-c1">0x0c</span>, <span class="pl-c1">0x1f</span>, <span class="pl-c1">0xb5</span>, <span class="pl-c1">0x9c</span>, <span class="pl-c1">0xb3</span>, <span class="pl-c1">0x1e</span>, <span class="pl-c1">0x36</span>, <span class="pl-c1">0xfb</span>, <span class="pl-c1">0x7d</span>,</td>
      </tr>
      <tr>
        <td id="L960" class="blob-num js-line-number" data-line-number="960"></td>
        <td id="LC960" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xcb</span>, <span class="pl-c1">0xb1</span>, <span class="pl-c1">0x77</span>, <span class="pl-c1">0x19</span>, <span class="pl-c1">0x57</span>, <span class="pl-c1">0x02</span>, <span class="pl-c1">0x15</span>, <span class="pl-c1">0x1b</span>, <span class="pl-c1">0xe7</span>, <span class="pl-c1">0x9a</span>, <span class="pl-c1">0x82</span>, <span class="pl-c1">0xca</span>, <span class="pl-c1">0x90</span>, <span class="pl-c1">0xc7</span>, <span class="pl-c1">0x56</span>, <span class="pl-c1">0xcb</span>,</td>
      </tr>
      <tr>
        <td id="L961" class="blob-num js-line-number" data-line-number="961"></td>
        <td id="LC961" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xd4</span>, <span class="pl-c1">0x72</span>, <span class="pl-c1">0x0f</span>, <span class="pl-c1">0xbf</span>, <span class="pl-c1">0x86</span>, <span class="pl-c1">0x83</span>, <span class="pl-c1">0x8d</span>, <span class="pl-c1">0xa0</span>, <span class="pl-c1">0x41</span>, <span class="pl-c1">0x9f</span>, <span class="pl-c1">0xc0</span>, <span class="pl-c1">0x5d</span>, <span class="pl-c1">0x49</span>, <span class="pl-c1">0xb8</span>, <span class="pl-c1">0x69</span>, <span class="pl-c1">0x0f</span>,</td>
      </tr>
      <tr>
        <td id="L962" class="blob-num js-line-number" data-line-number="962"></td>
        <td id="LC962" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xf0</span>, <span class="pl-c1">0xb3</span>, <span class="pl-c1">0x2b</span>, <span class="pl-c1">0x80</span>, <span class="pl-c1">0x86</span>, <span class="pl-c1">0xb8</span>, <span class="pl-c1">0xab</span>, <span class="pl-c1">0x29</span>, <span class="pl-c1">0xa8</span>, <span class="pl-c1">0x01</span>, <span class="pl-c1">0x60</span>, <span class="pl-c1">0x3e</span>, <span class="pl-c1">0x35</span>, <span class="pl-c1">0x5b</span>, <span class="pl-c1">0xc3</span>, <span class="pl-c1">0x81</span>,</td>
      </tr>
      <tr>
        <td id="L963" class="blob-num js-line-number" data-line-number="963"></td>
        <td id="LC963" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xf1</span>, <span class="pl-c1">0xbb</span>, <span class="pl-c1">0xae</span>, <span class="pl-c1">0xa9</span>, <span class="pl-c1">0xe5</span>, <span class="pl-c1">0x50</span>, <span class="pl-c1">0x0d</span>, <span class="pl-c1">0xca</span>, <span class="pl-c1">0x56</span>, <span class="pl-c1">0xcf</span>, <span class="pl-c1">0xc5</span>, <span class="pl-c1">0x86</span>, <span class="pl-c1">0xfd</span>, <span class="pl-c1">0xd8</span>, <span class="pl-c1">0xd4</span>, <span class="pl-c1">0xd4</span>,</td>
      </tr>
      <tr>
        <td id="L964" class="blob-num js-line-number" data-line-number="964"></td>
        <td id="LC964" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0xe7</span>, <span class="pl-c1">0x45</span>, <span class="pl-c1">0x11</span>, <span class="pl-c1">0x2e</span>, <span class="pl-c1">0x9f</span>, <span class="pl-c1">0x7d</span>, <span class="pl-c1">0x1f</span>, <span class="pl-c1">0x00</span>, <span class="pl-c1">0x00</span>, <span class="pl-c1">0xff</span>, <span class="pl-c1">0xff</span>, <span class="pl-c1">0x26</span>, <span class="pl-c1">0x20</span>, <span class="pl-c1">0x49</span>, <span class="pl-c1">0x28</span>, <span class="pl-c1">0xc6</span>,</td>
      </tr>
      <tr>
        <td id="L965" class="blob-num js-line-number" data-line-number="965"></td>
        <td id="LC965" class="blob-code blob-code-inner js-file-line">	<span class="pl-c1">0x13</span>, <span class="pl-c1">0x00</span>, <span class="pl-c1">0x00</span>,</td>
      </tr>
      <tr>
        <td id="L966" class="blob-num js-line-number" data-line-number="966"></td>
        <td id="LC966" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
</table>

  </div>

</div>

<button type="button" data-facebox="#jump-to-line" data-facebox-class="linejump" data-hotkey="l" class="d-none">Jump to Line</button>
<div id="jump-to-line" style="display:none">
  <!-- '"` --><!-- </textarea></xmp> --></option></form><form accept-charset="UTF-8" action="" class="js-jump-to-line-form" method="get"><div style="margin:0;padding:0;display:inline"><input name="utf8" type="hidden" value="&#x2713;" /></div>
    <input class="form-control linejump-input js-jump-to-line-field" type="text" placeholder="Jump to line&hellip;" aria-label="Jump to line" autofocus>
    <button type="submit" class="btn">Go</button>
</form></div>

  </div>
  <div class="modal-backdrop js-touch-events"></div>
</div>


    </div>
  </div>

    </div>

        <div class="container site-footer-container">
  <div class="site-footer" role="contentinfo">
    <ul class="site-footer-links float-right">
        <li><a href="https://github.com/contact" data-ga-click="Footer, go to contact, text:contact">Contact GitHub</a></li>
      <li><a href="https://developer.github.com" data-ga-click="Footer, go to api, text:api">API</a></li>
      <li><a href="https://training.github.com" data-ga-click="Footer, go to training, text:training">Training</a></li>
      <li><a href="https://shop.github.com" data-ga-click="Footer, go to shop, text:shop">Shop</a></li>
        <li><a href="https://github.com/blog" data-ga-click="Footer, go to blog, text:blog">Blog</a></li>
        <li><a href="https://github.com/about" data-ga-click="Footer, go to about, text:about">About</a></li>

    </ul>

    <a href="https://github.com" aria-label="Homepage" class="site-footer-mark" title="GitHub">
      <svg aria-hidden="true" class="octicon octicon-mark-github" height="24" version="1.1" viewBox="0 0 16 16" width="24"><path fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
</a>
    <ul class="site-footer-links">
      <li>&copy; 2017 <span title="0.06566s from github-fe-acdc16e.cp1-iad.github.net">GitHub</span>, Inc.</li>
        <li><a href="https://github.com/site/terms" data-ga-click="Footer, go to terms, text:terms">Terms</a></li>
        <li><a href="https://github.com/site/privacy" data-ga-click="Footer, go to privacy, text:privacy">Privacy</a></li>
        <li><a href="https://github.com/security" data-ga-click="Footer, go to security, text:security">Security</a></li>
        <li><a href="https://status.github.com/" data-ga-click="Footer, go to status, text:status">Status</a></li>
        <li><a href="https://help.github.com" data-ga-click="Footer, go to help, text:help">Help</a></li>
    </ul>
  </div>
</div>



    

    <div id="ajax-error-message" class="ajax-error-message flash flash-error">
      <svg aria-hidden="true" class="octicon octicon-alert" height="16" version="1.1" viewBox="0 0 16 16" width="16"><path fill-rule="evenodd" d="M8.865 1.52c-.18-.31-.51-.5-.87-.5s-.69.19-.87.5L.275 13.5c-.18.31-.18.69 0 1 .19.31.52.5.87.5h13.7c.36 0 .69-.19.86-.5.17-.31.18-.69.01-1L8.865 1.52zM8.995 13h-2v-2h2v2zm0-3h-2V6h2v4z"/></svg>
      <button type="button" class="flash-close js-flash-close js-ajax-error-dismiss" aria-label="Dismiss error">
        <svg aria-hidden="true" class="octicon octicon-x" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M7.48 8l3.75 3.75-1.48 1.48L6 9.48l-3.75 3.75-1.48-1.48L4.52 8 .77 4.25l1.48-1.48L6 6.52l3.75-3.75 1.48 1.48z"/></svg>
      </button>
      You can't perform that action at this time.
    </div>


      <script crossorigin="anonymous" src="https://assets-cdn.github.com/assets/compat-8e19569aacd39e737a14c8515582825f3c90d1794c0e5539f9b525b8eb8b5a8e.js"></script>
      <script crossorigin="anonymous" src="https://assets-cdn.github.com/assets/frameworks-bb39ae7d848d40d6f01e67355e282964f54fa39137c0ecc9fc4ec37e7d469508.js"></script>
      <script async="async" crossorigin="anonymous" src="https://assets-cdn.github.com/assets/github-89dfd8e3114312d4bf31b88163b763eb2dfee21bc0fa017e3eed09f3b85f8435.js"></script>
      
      
      
      
    <div class="js-stale-session-flash stale-session-flash flash flash-warn flash-banner d-none">
      <svg aria-hidden="true" class="octicon octicon-alert" height="16" version="1.1" viewBox="0 0 16 16" width="16"><path fill-rule="evenodd" d="M8.865 1.52c-.18-.31-.51-.5-.87-.5s-.69.19-.87.5L.275 13.5c-.18.31-.18.69 0 1 .19.31.52.5.87.5h13.7c.36 0 .69-.19.86-.5.17-.31.18-.69.01-1L8.865 1.52zM8.995 13h-2v-2h2v2zm0-3h-2V6h2v4z"/></svg>
      <span class="signed-in-tab-flash">You signed in with another tab or window. <a href="">Reload</a> to refresh your session.</span>
      <span class="signed-out-tab-flash">You signed out in another tab or window. <a href="">Reload</a> to refresh your session.</span>
    </div>
    <div class="facebox" id="facebox" style="display:none;">
  <div class="facebox-popup">
    <div class="facebox-content" role="dialog" aria-labelledby="facebox-header" aria-describedby="facebox-description">
    </div>
    <button type="button" class="facebox-close js-facebox-close" aria-label="Close modal">
      <svg aria-hidden="true" class="octicon octicon-x" height="16" version="1.1" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M7.48 8l3.75 3.75-1.48 1.48L6 9.48l-3.75 3.75-1.48-1.48L4.52 8 .77 4.25l1.48-1.48L6 6.52l3.75-3.75 1.48 1.48z"/></svg>
    </button>
  </div>
</div>

  </body>
</html>

