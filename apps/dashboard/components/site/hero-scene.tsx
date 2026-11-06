'use client'

import { useEffect, useRef } from 'react'
import * as THREE from 'three'

const BONE = '#ecebe4', LIME = '#c6ff2e', INK = '#141712'
const LANES = ['A', 'B', 'C']

/** The landing hero's figure, drawn with three.js: a release cut into layers, a scan frame passing through it,
 *  and validators A, B and C circling it on their own orbits. Decorative; without WebGL nothing is drawn. */
export function HeroScene() {
  const host = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const element = host.current
    if (!element) return
    let renderer: THREE.WebGLRenderer
    try { renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true }) } catch { return }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    element.prepend(renderer.domElement)

    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(30, 1, 0.1, 60)
    camera.position.set(0, 0, 13)
    const rig = new THREE.Group()
    rig.rotation.x = 0.42
    scene.add(rig)
    const disposable: { dispose: () => void }[] = []
    const keep = <T extends { dispose: () => void }>(item: T) => { disposable.push(item); return item }

    // The release: five layers that breathe apart slightly.
    const pack = new THREE.Group()
    rig.add(pack)
    const slabShape = keep(new THREE.BoxGeometry(2.7, 0.3, 2.7)), slabEdges = keep(new THREE.EdgesGeometry(slabShape))
    const slabs = Array.from({ length: 5 }, (_, index) => {
      const fill = keep(new THREE.MeshBasicMaterial({ color: INK, transparent: true, opacity: 0.86 }))
      const line = keep(new THREE.LineBasicMaterial({ color: BONE, transparent: true, opacity: 0.5 }))
      const group = new THREE.Group()
      group.add(new THREE.Mesh(slabShape, fill), new THREE.LineSegments(slabEdges, line))
      pack.add(group)
      return { group, line, level: index - 2 }
    })

    // The scan frame that travels up and down through the layers.
    const half = 1.95
    const frameShape = keep(new THREE.BufferGeometry().setFromPoints([[-half, -half], [half, -half], [half, half], [-half, half]].map(([x, z]) => new THREE.Vector3(x, 0, z))))
    const frame = new THREE.LineLoop(frameShape, keep(new THREE.LineBasicMaterial({ color: LIME })))
    const sheet = new THREE.Mesh(keep(new THREE.PlaneGeometry(half * 2, half * 2)), keep(new THREE.MeshBasicMaterial({ color: LIME, transparent: true, opacity: 0.06, side: THREE.DoubleSide, depthWrite: false })))
    sheet.rotation.x = -Math.PI / 2
    const scan = new THREE.Group()
    scan.add(frame, sheet)
    pack.add(scan)

    // Three validators, each on its own tilted orbit.
    const ringShape = keep(new THREE.BufferGeometry().setFromPoints(Array.from({ length: 128 }, (_, index) => { const angle = index / 128 * Math.PI * 2; return new THREE.Vector3(Math.cos(angle), 0, Math.sin(angle)) })))
    const probeShape = keep(new THREE.SphereGeometry(0.085, 20, 20))
    const orbits = LANES.map((_, index) => {
      const radius = 3.25 + index * 0.42
      const tilt = new THREE.Group()
      tilt.rotation.set([0.5, -0.36, 0.1][index], 0, [0.2, -0.3, 0.62][index])
      const ring = new THREE.LineLoop(ringShape, keep(new THREE.LineBasicMaterial({ color: BONE, transparent: true, opacity: 0.16 })))
      ring.scale.setScalar(radius)
      const probe = new THREE.Mesh(probeShape, keep(new THREE.MeshBasicMaterial({ color: BONE })))
      tilt.add(ring, probe)
      rig.add(tilt)
      return { probe, radius, speed: [0.42, -0.31, 0.24][index], phase: index * 2.1 }
    })

    // Sparse dust for depth.
    const dust = keep(new THREE.BufferGeometry())
    const points = new Float32Array(180 * 3)
    for (let index = 0; index < points.length; index += 3) {
      const radius = 3 + Math.random() * 3.4, angle = Math.random() * Math.PI * 2
      points[index] = Math.cos(angle) * radius; points[index + 1] = (Math.random() - 0.5) * 5; points[index + 2] = Math.sin(angle) * radius
    }
    dust.setAttribute('position', new THREE.BufferAttribute(points, 3))
    const cloud = new THREE.Points(dust, keep(new THREE.PointsMaterial({ color: BONE, size: 0.022, transparent: true, opacity: 0.4 })))
    rig.add(cloud)

    const labels = Array.from(element.querySelectorAll<HTMLElement>('[data-probe]'))
    const lime = new THREE.Color(LIME), bone = new THREE.Color(BONE), spot = new THREE.Vector3()
    const pointer = { x: 0, y: 0 }
    const size = { width: 1, height: 1 }
    const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches

    const draw = (time: number) => {
      const t = time / 1000
      pack.rotation.y = t * 0.22
      cloud.rotation.y = -t * 0.03
      const gap = 0.47 + Math.sin(t * 0.7) * 0.05
      scan.position.y = Math.sin(t * 0.85) * 1.35
      for (const slab of slabs) {
        slab.group.position.y = slab.level * gap
        const near = Math.max(0, 1 - Math.abs(slab.group.position.y - scan.position.y) / 0.42)
        slab.line.color.copy(bone).lerp(lime, near)
        slab.line.opacity = 0.42 + near * 0.58
        slab.group.scale.setScalar(1 + near * 0.035)
      }
      rig.rotation.y += (pointer.x * 0.28 - rig.rotation.y) * 0.05
      rig.rotation.x += (0.42 + pointer.y * 0.14 - rig.rotation.x) * 0.05
      orbits.forEach((orbit, index) => {
        const angle = orbit.phase + t * orbit.speed
        orbit.probe.position.set(Math.cos(angle) * orbit.radius, 0, Math.sin(angle) * orbit.radius)
        const label = labels[index]
        if (!label) return
        orbit.probe.getWorldPosition(spot).project(camera)
        label.style.transform = `translate(${(spot.x * 0.5 + 0.5) * size.width}px, ${(-spot.y * 0.5 + 0.5) * size.height}px)`
        label.style.opacity = '1'
      })
      renderer.render(scene, camera)
    }

    let frameId = 0, visible = true
    const loop = (time: number) => { draw(time); frameId = requestAnimationFrame(loop) }
    const start = () => { cancelAnimationFrame(frameId); if (still) draw(2400); else if (visible && !document.hidden) frameId = requestAnimationFrame(loop) }
    const resize = () => {
      size.width = element.clientWidth; size.height = element.clientHeight
      if (!size.width || !size.height) return
      renderer.setSize(size.width, size.height, false)
      camera.aspect = size.width / size.height
      camera.updateProjectionMatrix()
      if (still) draw(2400)
    }
    const move = (event: PointerEvent) => { pointer.x = event.clientX / window.innerWidth - 0.5; pointer.y = event.clientY / window.innerHeight - 0.5 }
    const sizes = new ResizeObserver(resize)
    sizes.observe(element)
    const seen = new IntersectionObserver(([entry]) => { visible = entry.isIntersecting; start() })
    seen.observe(element)
    window.addEventListener('pointermove', move)
    document.addEventListener('visibilitychange', start)
    resize(); start()

    return () => {
      cancelAnimationFrame(frameId); sizes.disconnect(); seen.disconnect()
      window.removeEventListener('pointermove', move); document.removeEventListener('visibilitychange', start)
      for (const item of disposable) item.dispose()
      renderer.dispose(); renderer.domElement.remove()
    }
  }, [])

  return <div className="lp-scene" ref={host} aria-hidden="true">
    {LANES.map((lane) => <span className="lp-probe" data-probe={lane} key={lane}><b>{lane}</b></span>)}
  </div>
}
